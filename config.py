"""config.py — load and save usb_blocker.ini"""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG = Path(__file__).resolve().parent / "usb_blocker.ini"

POLICY_DEFAULT_DENY = "default_deny"
POLICY_SCAN_AND_BLOCK = "scan_and_block"
POLICY_MODES = (POLICY_DEFAULT_DENY, POLICY_SCAN_AND_BLOCK)

HID_CLASSES = {
    "{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}",
    "{4D36E96B-E325-11CE-BFC1-08002BE10318}",
    "{4D36E96F-E325-11CE-BFC1-08002BE10318}",
}
STORAGE_CLASSES = {
    "{4D36E967-E325-11CE-BFC1-08002BE10318}",
    "{4D36E980-E325-11CE-BFC1-08002BE10318}",
    "{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}",
}


@dataclass
class DeviceID:
    vendor_id: str
    product_id: str
    serial: str = "*"

    @classmethod
    def parse(cls, s: str):
        parts = [p.strip() for p in s.split(":")]
        if len(parts) < 2:
            raise ValueError("Bad device spec — expected VID:PID[:Serial]")
        return cls(parts[0].lower(), parts[1].lower(),
                   parts[2].lower() if len(parts) > 2 else "*")

    def format(self):
        return f"{self.vendor_id}:{self.product_id}" if self.serial == "*" \
            else f"{self.vendor_id}:{self.product_id}:{self.serial}"


@dataclass
class Config:
    policy_mode: str = POLICY_DEFAULT_DENY
    block_action: str = "disable"
    poll_interval: int = 2
    log_file: Path = field(default_factory=lambda: Path(
        "C:/ProgramData/USBBlocker/usb_blocker.log"))
    log_level: str = "INFO"
    use_event_log: bool = True
    hid_popup_timeout: int = 30
    defender_scan_timeout: int = 60
    allow_unknown: bool = False
    whitelist: list[DeviceID] = field(default_factory=list)
    blacklist: list[DeviceID] = field(default_factory=list)


def _sections(ini: configparser.ConfigParser, *names: str) -> list[str]:
    lower = {s.lower(): s for s in ini.sections()}
    return [lower[n.lower()] for n in names if n.lower() in lower]


def _devices(ini: configparser.ConfigParser, *section_names: str) -> list[DeviceID]:
    out, seen = [], set()
    for sec in _sections(ini, *section_names):
        for key, val in ini[sec].items():
            if not key.startswith("device_"):
                continue
            try:
                spec = DeviceID.parse(val).format()
            except ValueError as e:
                print(f"[config] {e}")
                continue
            if spec not in seen:
                seen.add(spec)
                out.append(DeviceID.parse(val))
    return out


def load(path: Path = DEFAULT_CONFIG) -> Config:
    cfg = Config()
    if not path.exists():
        return cfg

    ini = configparser.ConfigParser(inline_comment_prefixes=("#",), strict=False)
    ini.read(path, encoding="utf-8")

    def opt(sec, key, default=None):
        return ini.get(sec, key, fallback=default) if ini.has_option(sec, key) else default

    def asbool(sec, key, default=False):
        v = opt(sec, key)
        return v.strip().lower() in ("true", "1", "yes") if v else default

    def asint(sec, key, default=0):
        v = opt(sec, key)
        try:
            return int(v) if v else default
        except ValueError:
            return default

    policy = (opt("global", "policy_mode") or POLICY_DEFAULT_DENY).lower()
    cfg.policy_mode = policy if policy in POLICY_MODES else POLICY_DEFAULT_DENY
    cfg.block_action = (opt("global", "block_action") or "disable").lower()
    cfg.poll_interval = asint("global", "poll_interval", 2)
    if lf := opt("logging", "log_file"):
        cfg.log_file = Path(lf)
    cfg.log_level = (opt("logging", "log_level") or "INFO").upper()
    cfg.use_event_log = asbool("logging", "use_event_log", True)
    cfg.hid_popup_timeout = asint("hid", "popup_timeout", 30)
    cfg.defender_scan_timeout = asint("defender", "scan_timeout", 60)
    cfg.allow_unknown = asbool("defender", "allow_unknown", False)
    cfg.whitelist = _devices(ini, "whitelist", "whitelist")
    cfg.blacklist = _devices(ini, "blacklist", "blacklist")
    return cfg


def save(cfg: Config, path: Path = DEFAULT_CONFIG) -> None:
    """Write config back to the ini file."""
    ini = configparser.ConfigParser(inline_comment_prefixes=("#",), strict=False)
    if path.exists():
        ini.read(path, encoding="utf-8")

    for section in ("global", "logging", "hid", "defender", "whitelist", "blacklist"):
        if section not in ini:
            ini.add_section(section)

    ini["global"]["policy_mode"] = cfg.policy_mode
    ini["global"]["block_action"] = cfg.block_action
    ini["global"]["poll_interval"] = str(cfg.poll_interval)

    ini["logging"]["log_file"] = str(cfg.log_file).replace("\\", "/")
    ini["logging"]["log_level"] = cfg.log_level
    ini["logging"]["use_event_log"] = "true" if cfg.use_event_log else "false"

    ini["hid"]["popup_timeout"] = str(cfg.hid_popup_timeout)

    ini["defender"]["scan_timeout"] = str(cfg.defender_scan_timeout)
    ini["defender"]["allow_unknown"] = "true" if cfg.allow_unknown else "false"

    for section, devices in (("whitelist", cfg.whitelist), ("blacklist", cfg.blacklist)):
        for key in list(ini[section]):
            if key.startswith("device_"):
                del ini[section][key]
        for i, dev in enumerate(devices, 1):
            ini[section][f"device_{i}"] = dev.format()

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        ini.write(f)


def set_policy_mode(cfg: Config, mode: str) -> Config:
    mode = mode.lower()
    if mode not in POLICY_MODES:
        raise ValueError(f"Unknown policy mode '{mode}' — use: {', '.join(POLICY_MODES)}")
    cfg.policy_mode = mode
    return cfg


def add_device(cfg: Config, list_name: str, spec: str) -> Config:
    if list_name not in ("whitelist", "blacklist"):
        raise ValueError("List must be 'whitelist' or 'blacklist'")
    dev = DeviceID.parse(spec)
    target = cfg.whitelist if list_name == "whitelist" else cfg.blacklist
    if any(d.format() == dev.format() for d in target):
        raise ValueError(f"{dev.format()} is already on the {list_name}")
    target.append(dev)
    return cfg


def remove_device(cfg: Config, list_name: str, spec: str) -> Config:
    if list_name not in ("whitelist", "blacklist"):
        raise ValueError("List must be 'whitelist' or 'blacklist'")
    dev = DeviceID.parse(spec)
    target = cfg.whitelist if list_name == "whitelist" else cfg.blacklist
    filtered = [d for d in target if d.format() != dev.format()]
    if len(filtered) == len(target):
        raise ValueError(f"{dev.format()} not found on the {list_name}")
    if list_name == "whitelist":
        cfg.whitelist = filtered
    else:
        cfg.blacklist = filtered
    return cfg


def full_config(cfg: Config):
    print(f"  policy_mode={cfg.policy_mode}  allow_unknown={cfg.allow_unknown}  "
          f"whitelist={len(cfg.whitelist)}  blacklist={len(cfg.blacklist)}")

    for label, items in (("whitelist", cfg.whitelist), ("blacklist", cfg.blacklist)):
        for d in items:
            print(f"    {label}: {d.format()}")
