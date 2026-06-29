import csv
import datetime
import os
import platform
import stat
import subprocess
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

import psutil

# SUSPICIOUS_EXTENSIONS = {".exe", ".cmd", ".bat", ".vbs", ".ps1", ".dll"}
SUSPICIOUS_EXTENSIONS = {
    # Executables
    ".exe", ".msi", ".dll", ".sys", ".scr", ".cpl", ".com",

    # Scripts
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", 

    # Shortcuts
    ".lnk",

    # Macro documents
    ".docm", ".xlsm", ".pptm",

    # Archives
    ".zip", ".rar", ".7z", ".iso", 

    # Web files
    ".html", ".htm", ".hta"
}

class USBSecurityManager:
    def __init__(self, log_path: str, poll_interval: int = 2):
        self.log_path = log_path
        self.poll_interval = poll_interval
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._known_drives: Set[str] = set()
        self._status_lock = threading.Lock()
        self._status = "STOPPED"
        self._blocked_drives: Set[str] = set()

    @property
    def status(self) -> str:
        with self._status_lock:
            return self._status

    def start(self, scan_existing: bool = True) -> bool:
        with self._status_lock:
            if self._monitor_thread and self._monitor_thread.is_alive():
                return False

            self._stop_event.clear()
            self._status = "ACTIVE"
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                kwargs={"scan_existing": scan_existing},
                daemon=True,
            )
            self._monitor_thread.start()

        self._log_event("MONITOR", "SYSTEM", "ACTIVE", "USB monitoring started")
        return True

    def stop(self) -> bool:
        with self._status_lock:
            if not self._monitor_thread or not self._monitor_thread.is_alive():
                self._status = "STOPPED"
                return False

            self._stop_event.set()
            monitor_thread = self._monitor_thread

        monitor_thread.join(timeout=3)

        with self._status_lock:
            self._status = "STOPPED"

        self._log_event("MONITOR", "SYSTEM", "STOPPED", "USB monitoring stopped")
        return True

    def get_connected_devices(self) -> List[Dict[str, str]]:
        return self._detect_usb_drives()

    def get_blocked_drives(self) -> List[str]:
        return sorted(self._blocked_drives)

    def _monitor_loop(self, scan_existing: bool):
        devices = self._detect_usb_drives()
        self._known_drives = {d["mountpoint"] for d in devices}

        if scan_existing:
            for drive in self._known_drives:
                self._process_inserted_drive(drive, inserted=False)

        while not self._stop_event.is_set():
            devices = self._detect_usb_drives()
            current_drives = {d["mountpoint"] for d in devices}
            new_drives = current_drives - self._known_drives

            for drive in new_drives:
                self._process_inserted_drive(drive, inserted=True)

            self._known_drives = current_drives
            time.sleep(self.poll_interval)

    def _process_inserted_drive(self, drive: str, inserted: bool = True):
        # report insertion or detection
        if inserted:
            self._log_event("USB_INSERTED", drive, "DETECTED", "USB drive inserted")
        else:
            self._log_event("USB_DETECTED", drive, "DETECTED", "USB drive detected at monitor startup")

        # if the drive was previously blocked, don't attempt to scan it again
        if drive in self._blocked_drives:
            self._log_event(
                "BLOCK",
                drive,
                "ALREADY_BLOCKED",
                "Drive re‑appeared but was already marked blocked; skipping scan",
            )
            return

        # perform scan, catching permission errors that may occur on a blocked drive
        try:
            malicious, file_found = self.scan_drive(drive)
        except PermissionError:
            # if we can't read the drive contents it may have been restricted
            # treat as malicious so the user is warned and drive remains blocked
            self._log_event(
                "SCAN",
                drive,
                "MALICIOUS",
                "Unable to access drive contents (permission denied)",
            )
            self.block_drive(drive, None)
            return

        if malicious:
            self._log_event("SCAN", drive, "MALICIOUS", f"Malicious file found: {file_found}")
            self.block_drive(drive, file_found)
            return

        self._log_event("SCAN", drive, "SAFE", "No suspicious files detected")

    def scan_drive(self, path: str) -> Tuple[bool, Optional[str]]:
        for root, _, files in os.walk(path):
            for file_name in files:
                extension = os.path.splitext(file_name)[1].lower()
                if extension in SUSPICIOUS_EXTENSIONS:
                    return True, os.path.join(root, file_name)
        return False, None

    def block_drive(self, drive: str, file_found: Optional[str] = None):
        block_details = []

        unmounted, unmount_message = self._unmount_drive(drive)
        block_details.append(unmount_message)

        if os.path.exists(drive):
            try:
                self._restrict_permissions(drive)
                block_details.append("permissions_restricted")
            except OSError as error:
                block_details.append(f"permission_change_failed:{error}")

        self._blocked_drives.add(drive)

        details = "Drive marked as blocked"
        if file_found:
            details += f" due to {file_found}"
        details += f" ({', '.join(block_details)})"
        status = "BLOCKED" if unmounted else "BLOCK_ATTEMPTED"

        self._log_event("BLOCK", drive, status, details)

    def _unmount_drive(self, drive: str) -> Tuple[bool, str]:
        system = platform.system().lower()

        try:
            if system == "windows":
                drive_letter = drive.rstrip("\\/")
                result = subprocess.run(
                    ["mountvol", drive_letter, "/p"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    return True, "windows_mountvol_unmounted"
                error = (result.stderr or result.stdout or "unknown error").strip()
                return False, f"windows_unmount_failed:{error}"

            result = subprocess.run(["umount", drive], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return True, "unix_umount_success"

            error = (result.stderr or result.stdout or "unknown error").strip()
            return False, f"unix_umount_failed:{error}"
        except FileNotFoundError:
            return False, "unmount_command_not_found"

    def _restrict_permissions(self, root_path: str):
        os.chmod(root_path, stat.S_IRUSR | stat.S_IXUSR)
        for root, dirs, files in os.walk(root_path):
            for dir_name in dirs:
                path = os.path.join(root, dir_name)
                os.chmod(path, stat.S_IRUSR | stat.S_IXUSR)
            for file_name in files:
                path = os.path.join(root, file_name)
                os.chmod(path, stat.S_IRUSR)

    def _detect_usb_drives(self) -> List[Dict[str, str]]:
        devices = []
        for partition in psutil.disk_partitions(all=False):
            if self._is_usb_partition(partition):
                devices.append(
                    {
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "options": partition.opts,
                        "is_blocked": partition.mountpoint in self._blocked_drives,
                    }
                )
        return devices

    @staticmethod
    def _is_usb_partition(partition) -> bool:
        opts = partition.opts.lower()
        device = partition.device.lower()
        mountpoint = partition.mountpoint.lower()

        return (
            "removable" in opts
            or "usb" in device
            or "/media/" in mountpoint
            or "/run/media/" in mountpoint
            or mountpoint.startswith("e:\\")
            or mountpoint.startswith("f:\\")
            or mountpoint.startswith("g:\\")
        )

    def _log_event(self, event_type: str, drive: str, status: str, details: str):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        row = [
            datetime.datetime.now().isoformat(timespec="seconds"),
            event_type,
            drive,
            status,
            details,
        ]

        with open(self.log_path, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(row)
