import time
import psutil
import subprocess
import ctypes

print("🛡️ Sentinel Guard Phase 2 – USB Monitoring Started")

known_drives = set()

def show_popup(message, title="Sentinel Guard"):
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)

def get_usb_drives():
    drives = set()
    for p in psutil.disk_partitions():
        if 'removable' in p.opts.lower():
            drives.add(p.device)
    return drives

while True:
    current_drives = get_usb_drives()
    new_drives = current_drives - known_drives

    for drive in new_drives:
        print(f"\n⚠️ USB INSERTED: {drive}")

        # 🔔 SHOW MESSAGE IMMEDIATELY
        show_popup(
            f"USB device detected on {drive}\nSentinel Guard is monitoring this device.",
            "USB Detected"
        )

        # 🔍 START SCANNING
        subprocess.call(["python", "usb_scanner.py", drive])

    known_drives = current_drives
    time.sleep(2)
