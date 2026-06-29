import sys

from usb_security import USBSecurityManager

if __name__ == "__main__":
    drive = sys.argv[1]
    manager = USBSecurityManager("../data/intrusion_log.csv")
    malicious, file_found = manager.scan_drive(drive)

    if malicious:
        manager.block_drive(drive, file_found)
        print(f"Blocked {drive} due to suspicious file: {file_found}")
    else:
        print(f"{drive} is safe")
