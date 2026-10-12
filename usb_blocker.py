from __future__ import annotations
import pythoncom
import argparse
import ctypes
import fnmatch
import logging
import logging.handlers
import re
import subprocess
import sys
import threading
import time
import winreg
from pathlib import Path

import config as cfg_module
from config import (
    Config, DEFAULT_CONFIG, HID_CLASSES, STORAGE_CLASSES,
    POLICY_DEFAULT_DENY, POLICY_SCAN_AND_BLOCK, POLICY_MODES,
    add_device, remove_device, save, set_policy_mode,
)

try:
    from usbmonitor import USBMonitor

    ID_MODEL = "ID_MODEL"
    ID_MODEL_ID = "ID_MODEL_ID"
    ID_VENDOR_ID = "ID_VENDOR_ID"
    ID_SERIAL = "ID_SERIAL"
    ID_USB_CLASS = "ID_USB_CLASS"

except ImportError as e:
    print(e)
    sys.exit("usb-monitor import failed")

try:
    import wmi
    import win32service
    import win32serviceutil
    import servicemanager
except ImportError:
    sys.exit("Run: pip install pywin32 wmi && python -m pywin32_postinstall -install")

VERSION, SERVICE_NAME = "1.2.0", "USBBlocker"
MPCMDRUN = Path("C:/Program Files/Windows Defender/MpCmdRun.exe")
log = logging.getLogger(__name__)

# FIX: guard the shared set with a lock to prevent race conditions across threads
_disabled_devices: set[str] = set()
_disabled_devices_lock = threading.Lock()

# FIX: sentinel constant instead of magic number 99
_KEYBOARD_FAIL_SAFE = float("inf")

# FIX: lock to serialize the write-protect toggle in _grant_storage_rw,
# preventing concurrent storage evaluations from racing on the global registry key
_storage_lock = threading.Lock()

# FIX: regex for validating device IDs before passing to pnputil
_DEVICE_ID_RE = re.compile(
    r"^USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}", re.IGNORECASE
)


# setup logger file and logging for the usb blocker, sets level and format
def setup_logging(cfg: Config):
    cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)-7s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    log.setLevel(cfg.log_level)
    log.handlers.clear()
    handlers: list[logging.Handler] = [
        logging.FileHandler(cfg.log_file, encoding="utf-8"),
        logging.StreamHandler(),
    ]
    if cfg.use_event_log and servicemanager.RunningAsService():
        handlers.append(logging.handlers.NTEventLogHandler(SERVICE_NAME))
    for h in handlers:
        h.setFormatter(fmt)
        log.addHandler(h)


def count_keyboards() -> float:
    """Return the number of keyboards visible to WMI, or _KEYBOARD_FAIL_SAFE on error."""
    try:
        return len(wmi.WMI().Win32_Keyboard())
    except Exception:
        log.error("Failed to query keyboard count — assuming multiple keyboards present")
        return _KEYBOARD_FAIL_SAFE


def set_usb_write_protect(enable: bool):
    """Toggles global USB write protection via the registry."""
    try:
        # Create or open the StorageDevicePolicies key
        key = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
        )
        # 1 = Read Only, 0 = Read/Write
        winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1 if enable else 0)
        winreg.CloseKey(key)
        log.info("USB WriteProtect set to: %s", enable)
    except Exception as e:
        log.error("Failed to set WriteProtect: %s", e)


def _validate_device_id(device_id: str) -> bool:
    """
    FIX: validate device_id format before passing to pnputil.
    Device IDs come from WMI which is attacker-influenced via USB descriptor strings.
    """
    if not _DEVICE_ID_RE.match(device_id):
        log.warning("Rejected suspicious device ID: %r", device_id)
        return False
    return True


# the pnputil (specifically windows)
def pnp(action: str, device_id: str) -> bool:
    # FIX: validate before shelling out
    if not _validate_device_id(device_id):
        return False

    try:
        r = subprocess.run(
            ["pnputil", f"/{action}-device", device_id.strip()],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        log.exception("pnputil crashed")
        return False

    out = r.stdout.lower()

    if r.returncode == 0 and "restart" not in out and "reboot" not in out:
        # If it returns 0 BUT asks for a restart, it failed to disable immediately due to open handles.
        # FIX: hold the lock while mutating the shared set
        with _disabled_devices_lock:
            if action == "disable":
                _disabled_devices.add(device_id.strip())
            elif action == "enable":
                _disabled_devices.discard(device_id.strip())

        log.log(
            logging.WARNING if action == "disable" else logging.INFO,
            "%s %s",
            action.upper(),
            device_id,
        )
        return True

    err_msg = r.stdout.strip() if r.stdout else r.stderr.strip()
    log.error("pnputil %s failed/locked: %s", action, err_msg)
    return False


# log and disable when devices get blocked
def block(device_id: str, reason: str):
    """
    Disable a device and retry while Defender holds an open quarantine handle.
    """
    log.warning("BLOCK %s — %s", device_id, reason)

    # Defender holds a lock on the drive while quarantining files.
    # We loop and wait until it releases the handle.
    for attempt in range(1, 6):
        if pnp("disable", device_id):
            log.info("Successfully forced block on attempt %d", attempt)
            return
        log.warning(
            "Drive locked by Defender quarantine. Retrying in 5 s... (%d/5)", attempt
        )
        time.sleep(5)

    log.error("CRITICAL: Failed to force-disable %s after multiple attempts.", device_id)


# check if its in the list
def listed(devices, vid: str, pid: str, serial: str) -> bool:
    return any(
        fnmatch.fnmatch(vid, d.vendor_id)
        and fnmatch.fnmatch(pid, d.product_id)
        and fnmatch.fnmatch(serial, d.serial)
        for d in devices
    )


# scans the drives, also checks with the system
def scan_drive(cfg: Config, drive: str) -> str:
    path = f"{drive}\\"  # e.g., D:\
    log.info("Defender scan %s", path)
    try:
        # 1. Run the manual scan
        r = subprocess.run(
            [str(MPCMDRUN), "-Scan", "-ScanType", "3", "-File", path],
            capture_output=True,
            text=True,
            timeout=cfg.defender_scan_timeout * 60,
        )

        # 2. Check if Real-Time Protection caught something on this drive
        # FIX: use re.escape so the drive letter is safe inside the regex pattern
        escaped_drive = re.escape(drive)
        ps_cmd = (
            f"Get-MpThreatDetection | Where-Object {{ "
            f"$_.Resources -match '{escaped_drive}\\\\' -and "
            f"$_.InitialDetectionTime -gt (Get-Date).AddMinutes(-2) }} | "
            f"Measure-Object | Select-Object -ExpandProperty Count"
        )

        # Added ExecutionPolicy Bypass so Windows doesn't block the background command
        ps_check = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
        )

        # Safely parse the output to see if a threat was counted
        count_str = ps_check.stdout.strip()
        rtp_caught = count_str.isdigit() and int(count_str) > 0

        # If either the manual scan finds it OR RTP already removed it, flag it
        if r.returncode == 2 or rtp_caught:
            log.warning(
                "Defender: threat found on %s (RTP Intercept: %s)", path, rtp_caught
            )
            return "flagged"

        if r.returncode == 0:
            return "clean"

    except subprocess.TimeoutExpired:
        log.error("Defender: scan timed out")
    except Exception as e:
        log.error("Defender error: %s", e)
    return "unknown"


def get_all_drives() -> set[str]:
    # DriveType 2 = Removable, 3 = Local/UAS
    try:
        return {
            disk.DeviceID
            for disk in wmi.WMI().Win32_LogicalDisk()
            if disk.DriveType in (2, 3)
        }
    except Exception:
        log.exception("Drive lookup failed")
        return set()


def _grant_storage_rw(device_id: str, vid: str, pid: str):
    log.info("STORAGE ALLOW %s:%s - Scan passed, preparing read/write access...", vid, pid)
    with _storage_lock:
        time.sleep(3)
        pnp("disable", device_id)
        set_usb_write_protect(False)
        time.sleep(2)
        pnp("enable", device_id)
        time.sleep(4)
        set_usb_write_protect(True)
    log.info("STORAGE FULL ACCESS GRANTED %s:%s", vid, pid)


def _handle_storage_scan(cfg: Config, device_id: str, vid: str, pid: str):
    """Disable the device, wait for a drive letter, scan, then allow or block."""
    pnp("disable", device_id)
    drives_before = get_all_drives()
    pnp("enable", device_id)

    new_drives: set[str] = set()
    for _ in range(cfg.drive_assign_timeout if hasattr(cfg, "drive_assign_timeout") else 15):
        time.sleep(1)
        new_drives = get_all_drives() - drives_before
        if new_drives:
            break

    if not new_drives:
        block(device_id, "storage — no drive letter assigned")
        return

    for drive in new_drives:
        result = scan_drive(cfg, drive)
        allow = result == "clean" or (result == "unknown" and cfg.allow_unknown)
        if not allow:
            block(device_id, f"storage threat on {drive} (status: {result})")
            return

    _grant_storage_rw(device_id, vid, pid)


def handle_device(
    cfg: Config,
    device_id: str,
    vid: str,
    pid: str,
    name: str,
    serial: str,
    kind: str,
):
    if listed(cfg.blacklist, vid, pid, serial):
        block(device_id, f"{kind} on blacklist")
        return

    if listed(cfg.whitelist, vid, pid, serial):
        log.info("%s ALLOW (whitelist) %s:%s", kind.upper(), vid, pid)
        return

    if kind == "hid":
        if count_keyboards() <= 1:
            log.info("HID ALLOW (auto — single keyboard) %s:%s", vid, pid)
            return
        block(device_id, "HID denied (multiple keyboards detected)")
        return

    if kind == "storage" and cfg.policy_mode == POLICY_SCAN_AND_BLOCK:
        _handle_storage_scan(cfg, device_id, vid, pid)
        return

    block(device_id, f"{kind} not on whitelist ({cfg.policy_mode})")


def safe_handle(*args):
    pythoncom.CoInitialize()
    try:
        handle_device(*args)
    except Exception:
        log.exception("handle_device crashed")
    finally:
        pythoncom.CoUninitialize()


# the actual monitor process for connects and disconnects
def monitor(cfg: Config, stop: threading.Event | None = None):

    def on_connect(device_id: str, info: dict):
        vid    = (info.get(ID_VENDOR_ID) or "????").lower()
        pid    = (info.get(ID_MODEL_ID)  or "????").lower()
        name   = info.get(ID_MODEL) or ""
        serial = (info.get(ID_SERIAL)    or "").lower()
        guid   = (info.get(ID_USB_CLASS) or "").upper()

        if not guid:
            name_lower = name.lower()
            if any(x in name_lower for x in ("hid", "input", "keyboard", "mouse", "composite")):
                guid = "{4D36E96B-E325-11CE-BFC1-08002BE10318}"
            elif any(x in name_lower for x in ("storage", "mass storage", "disk", "scsi")):
                guid = "{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}"

        log.info("RAW CONNECT id=%s info=%s", device_id, info)
        log.info("CONNECT %s:%s class=%s '%s'", vid, pid, guid, name)

        kind = "hid" if guid in HID_CLASSES else "storage" if guid in STORAGE_CLASSES else "other"
        threading.Thread(
            target=safe_handle,
            args=(cfg, device_id, vid, pid, name, serial, kind),
            daemon=True,
        ).start()

    def on_disconnect(_id: str, info: dict):
        log.info(
            "REMOVE %s:%s",
            (info.get(ID_VENDOR_ID) or "?").lower(),
            (info.get(ID_MODEL_ID)  or "?").lower(),
        )

    log.info("USB Blocker v%s policy=%s", VERSION, cfg.policy_mode)
    stop = stop or threading.Event()
    usb = USBMonitor()

    # now actually monitor
    try:
        usb.start_monitoring(
            on_connect=on_connect,
            on_disconnect=on_disconnect,
            check_every_seconds=cfg.poll_interval,
        )
        stop.wait()
    except Exception:
        log.exception("USB monitor crashed")


# the windows service management function, starts and stops the service and also creates and names it accordingly.
class USBBlockerService(win32serviceutil.ServiceFramework):
    _svc_name_         = SERVICE_NAME
    _svc_display_name_ = "USB Blocker"
    _svc_description_  = "USB device policy enforcement"

    def __init__(self, args):
        super().__init__(args)
        self._stop = threading.Event()

    def SvcStop(self):
        cfg = cfg_module.load(DEFAULT_CONFIG)
        log.info("USB Blocker stopping...")
        
        # Unlock the system when the service stops
        set_usb_write_protect(False)
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop.set()

    def SvcDoRun(self):
        try:
            cfg = cfg_module.load(DEFAULT_CONFIG)
            setup_logging(cfg)
            log.info("USB Blocker v%s starting...", VERSION)
            
            # LOCK THE GATES IMMEDIATELY ON STARTUP
            set_usb_write_protect(True)
            disable_autoplay()
            disable_all_usb()
            enable_whitelisted(cfg)
            monitor(cfg, self._stop)
            log.info("Service stopped")
        except Exception as e:
            Path("C:/ProgramData/USBBlocker/crash.log").write_text(
                f"{e}\n{__import__('traceback').format_exc()}"
            )
            raise


# lists all devices currently connected to the system
def list_devices():
    print(f"\n{'VID:PID':<12} {'Name'}")
    print("-" * 50)
    for device in wmi.WMI().Win32_PnPEntity():
        pnp_id = device.PNPDeviceID or ""
        if "USB\\" not in pnp_id:
            continue
        vid, pid = "????", "????"
        for part in pnp_id.replace("USB\\", "").split("&"):
            if part.upper().startswith("VID_"):
                vid = part[4:8].lower()
            elif part.upper().startswith("PID_"):
                pid = part[4:8].lower()
        print(f"{vid}:{pid}    {device.Name or 'Unknown'}")


# disables the autoplay on the system, registry keys are best in this case.
def disable_autoplay():
    try:
        key = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        )
        winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, 255)
        winreg.CloseKey(key)
        log.info("Disabled AutoPlay/AutoRun for all drives")
    except Exception as e:
        log.error("Autoplay disable failed: %s", e)


# disables all usbs on start and such
def disable_all_usb():
    log.info("Disabling non-whitelisted removable USB devices...")
    try:
        result = subprocess.run(
            ["pnputil", "/enum-devices"],
            capture_output=True,
            text=True,
            timeout=20,
        )

        # FIX: collect the full instance ID then decide — don't clear current
        # after the first attribute line, because pnputil emits several lines
        # per device block between Instance ID entries.
        current_id: str | None = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Instance ID:"):
                # Process the previously collected device ID, if any
                if current_id is not None:
                    upper = current_id.upper()
                    dangerous = any(x in upper for x in ("USBSTOR", "VID_", "USB\\"))
                    ignore    = any(x in upper for x in ("ROOT_HUB", "HUB", "HOST_CONTROLLER"))
                    if dangerous and not ignore:
                        pnp("disable", current_id)
                current_id = stripped.split(":", 1)[1].strip()

        # Process the last device in the output
        if current_id is not None:
            upper = current_id.upper()
            dangerous = any(x in upper for x in ("USBSTOR", "VID_", "USB\\"))
            ignore    = any(x in upper for x in ("ROOT_HUB", "HUB", "HOST_CONTROLLER"))
            if dangerous and not ignore:
                pnp("disable", current_id)

    except Exception:
        log.exception("disable_all_usb failed")


# enables whitelisted devices if they are plugged in. This is mainly for startup of the service
def enable_whitelisted(cfg: Config):
    for device in wmi.WMI().Win32_PnPEntity():
        pnp_id = device.PNPDeviceID or ""
        if "USB\\" not in pnp_id:
            continue
        vid, pid = "????", "????"
        for part in pnp_id.replace("USB\\", "").split("&"):
            if part.upper().startswith("VID_"):
                vid = part[4:8].lower()
            elif part.upper().startswith("PID_"):
                pid = part[4:8].lower()
        log.info("Checking %s:%s — %s", vid, pid, pnp_id)
        # Use "*" serial wildcard to match entries whitelisted by VID:PID only,
        # consistent with how listed() is called during hotplug evaluation.
        if listed(cfg.whitelist, vid, pid, "*"):
            log.info("STARTUP ALLOW %s:%s — %s", vid, pid, pnp_id)
            pnp("enable", pnp_id)


# restores all usbs that were previously blocked and ports
def restore_all_usb():
    log.info("Restoring disabled USB devices...")
    try:
        # ConfigManagerErrorCode 22 means the device is manually disabled
        count = 0
        for device in wmi.WMI().Win32_PnPEntity():
            if (
                device.ConfigManagerErrorCode == 22
                and device.PNPDeviceID
                and "USB" in device.PNPDeviceID
            ):
                log.info("Restoring: %s", device.PNPDeviceID)
                pnp("enable", device.PNPDeviceID)
                count += 1
        log.info("Restored %d device(s).", count)
    except Exception as e:
        log.error("Restore failed: %s", e)


COMMANDS = [
    ("run",      "Start the USB monitor in the foreground"),
    ("list",     "List all currently connected USB devices (VID:PID and name)"),
    ("restore",  "Re-enable all USB devices that were previously disabled"),
    ("commands", "Show this list of available commands"),
    ("config",   "View or update policy, whitelist, and blacklist (see: config --help)"),
    ("install",  "Install USB Blocker as a Windows service"),
    ("start",    "Start the Windows service"),
    ("stop",     "Stop the Windows service"),
    ("restart",  "Restart the Windows service"),
    ("remove",   "Uninstall the Windows service"),
]


def print_commands():
    print(f"\nUSB Blocker v{VERSION} — available commands\n")
    for name, desc in COMMANDS:
        print(f"  {name:<12} {desc}")
    print(f"\nGlobal options: -c/--config <path>   --test-config")
    print(f"Policy modes:   {POLICY_DEFAULT_DENY} | {POLICY_SCAN_AND_BLOCK}")
    print(f"Device format:  VID:PID  or  VID:PID:serial  (e.g. 413c:2514)\n")


def handle_config_command(args, path: Path):
    cfg = cfg_module.load(path)

    if args.config_action == "show":
        print(f"Config: {path}")
        cfg_module.full_config(cfg)
        return

    if args.config_action == "set-policy":
        set_policy_mode(cfg, args.mode)
        save(cfg, path)
        print(f"Policy set to {cfg.policy_mode} (saved to {path})")
        return

    if args.config_action in (
        "whitelist-add", "whitelist-remove", "blacklist-add", "blacklist-remove"
    ):
        list_name, op = args.config_action.rsplit("-", 1)
        try:
            if op == "add":
                add_device(cfg, list_name, args.device)
            else:
                remove_device(cfg, list_name, args.device)
            save(cfg, path)
            print(f"{args.device} {op}ed on {list_name} (saved to {path})")
        except ValueError as e:
            sys.exit(str(e))


def main():
    p = argparse.ArgumentParser(description=f"USB Blocker v{VERSION}")
    p.add_argument("-c", "--config", default=str(DEFAULT_CONFIG))
    p.add_argument("--test-config", action="store_true")
    sub = p.add_subparsers(dest="action")

    sub.add_parser("run",      help="Start USB monitor in foreground")
    sub.add_parser("list",     help="List connected USB devices")
    sub.add_parser("restore",  help="Re-enable disabled USB devices")
    sub.add_parser("commands", help="List all available commands")

    cfg_p   = sub.add_parser("config", help="View or update configuration")
    cfg_sub = cfg_p.add_subparsers(dest="config_action", required=True)
    cfg_sub.add_parser("show", help="Print current configuration")

    pol = cfg_sub.add_parser("set-policy", help="Set policy mode")
    pol.add_argument(
        "mode",
        choices=list(POLICY_MODES),
        help=(
            f"{POLICY_DEFAULT_DENY}: block unknown devices; "
            f"{POLICY_SCAN_AND_BLOCK}: scan storage then block if flagged"
        ),
    )

    for list_name in ("whitelist", "blacklist"):
        add_p = cfg_sub.add_parser(f"{list_name}-add",  help=f"Add a device to the {list_name}")
        add_p.add_argument("device", help="VID:PID or VID:PID:serial")
        rm_p  = cfg_sub.add_parser(f"{list_name}-remove", help=f"Remove a device from the {list_name}")
        rm_p.add_argument("device", help="VID:PID or VID:PID:serial")

    for name in ("install", "start", "stop", "restart", "remove"):
        sub.add_parser(name, help=f"Windows service: {name}")

    args   = p.parse_args()
    path   = Path(args.config)
    action = args.action or "run"

    if args.test_config:
        cfg = cfg_module.load(path)
        print(f"Config: {path}")
        cfg_module.full_config(cfg)
        return

    if action == "commands":
        print_commands()
        return

    if action == "config":
        handle_config_command(args, path)
        return

    cfg = cfg_module.load(path)

    if action == "list":
        setup_logging(cfg)
        list_devices()
        return

    if action == "restore":
        setup_logging(cfg)
        restore_all_usb()
        return

    if action == "run":
        setup_logging(cfg)
        disable_autoplay()
        enable_whitelisted(cfg)
        monitor(cfg)
        return

    if action == "install":
        sys.argv = [sys.argv[0], "--startup=auto", "install"]
    else:
        sys.argv = [sys.argv[0], action]

    win32serviceutil.HandleCommandLine(USBBlockerService)


if __name__ == "__main__":
    main()