# USB Blocker

## Notes
VID = Vendor ID
PID = Product ID

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges (for `pnputil` device disable and the Windows service)
- Dependencies: `pip install -r requirements.txt`
- Post-install for pywin32: `python -m pywin32_postinstall -install`

## Quick start
```
- Run PowerShell as Administrator
    - cd path\to\USB
    - pip install -r requirements.txt
- Edit the config file
    - usb_blocker.ini
- Verify config
    - python usb_blocker.py --test-config
- Foreground monitor
    - python usb_blocker.py run
- Install as Windows service
    - python usb_blocker.py install
    - python usb_blocker.py start
    - python usb_blocker.py stop
    - python usb_blocker.py remove
- All Commands 
    - python usb_blocker.py install
    - python usb_blocker.py start
    - python usb_blocker.py stop
    - python usb_blocker.py remove
    - python usb_blocker.py --test-config #tests config file
    - python usb_blocker.py run
    - python usb_blocker.py list #lists all usb devices connected
    - python usb_blocker.py restore #restores all usb devices disabled
```

## Resources

- https://docs.python.org/3/library/configparser.html
- https://pypi.org/project/usb-monitor/
- https://github.com/HaroldMills/Python-Windows-Service-Example/blob/master/example_service.py
- https://docs.python.org/3/library/logging.html 
- https://www.geeksforgeeks.org/python/logging-in-python/


