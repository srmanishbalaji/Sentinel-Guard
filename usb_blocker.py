import sys

from usb_security import USBSecurityManager

if __name__ == "__main__":
    drive = sys.argv[1]
    manager = USBSecurityManager("../data/intrusion_log.csv")
    manager.block_drive(drive)
    print(f"Drive {drive} marked blocked")
