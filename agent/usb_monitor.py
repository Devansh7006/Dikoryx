"""
Advanced USB Intelligence Monitor
Windows-focused
Backend-compatible event format
"""

import hashlib
import os
import sys
import time
from typing import Any, Dict

SCAN_INTERVAL = 5
MAX_FILES_SCAN = 10000
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1",
    ".vbs", ".js", ".scr", ".cmd", ".pif"
}


def _is_windows() -> bool:
    return sys.platform == "win32"


def _wmi_client():
    import wmi

    return wmi.WMI()


# ==========================================================
# DEVICE ENUMERATION (WMI SAFE)
# ==========================================================

def enumerate_usb_devices():
    if not _is_windows():
        return []

    devices = []
    c = _wmi_client()

    for dev in c.Win32_PnPEntity():
        try:
            if not dev.PNPDeviceID:
                continue

            if "USB" not in dev.PNPDeviceID:
                continue

            device_info = {
                "name": dev.Name,
                "device_id": dev.PNPDeviceID,
                "description": dev.Description,
                "class": dev.PNPClass,
                "manufacturer": dev.Manufacturer,
                "location": getattr(dev, "LocationInformation", None),
            }

            if "VID_" in dev.PNPDeviceID:
                parts = dev.PNPDeviceID.split("\\")
                if len(parts) > 1:
                    device_info["vid_pid"] = parts[1]

            devices.append(device_info)

        except Exception:
            continue

    return devices


# ==========================================================
# DRIVE DETECTION
# ==========================================================

def detect_usb_mounts():
    if not _is_windows():
        return []

    mounts = []
    c = _wmi_client()

    for disk in c.Win32_DiskDrive():
        if disk.InterfaceType != "USB":
            continue

        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
            for logical in partition.associators("Win32_LogicalDiskToPartition"):
                mounts.append(logical.DeviceID + "\\")

    return mounts


# ==========================================================
# STORAGE SCAN
# ==========================================================

def scan_storage(mount: str):
    total_files = 0
    suspicious = []
    fingerprint_builder = []

    for root, _, files in os.walk(mount):
        for f in files:
            if total_files >= MAX_FILES_SCAN:
                break

            try:
                full = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()

                total_files += 1

                if ext in SUSPICIOUS_EXTENSIONS:
                    suspicious.append(f)

                stat = os.stat(full)
                fingerprint_builder.append(
                    f"{f}:{stat.st_size}:{int(stat.st_mtime)}"
                )

            except Exception:
                continue

    fingerprint = hashlib.sha256(
        "\n".join(sorted(fingerprint_builder)).encode()
    ).hexdigest()

    risk_score = len(suspicious)

    if risk_score > 20:
        risk_level = "HIGH"
    elif risk_score > 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "total_files": total_files,
        "suspicious_files": suspicious[:20],
        "fingerprint": fingerprint,
        "risk": risk_level
    }


# ==========================================================
# DEVICE RISK CLASSIFICATION
# ==========================================================

def classify_device(device: Dict[str, Any]):
    device_class = (device.get("class") or "").lower()

    if "hid" in device_class:
        return "LOW"
    if "bluetooth" in device_class:
        return "MEDIUM"
    if "diskdrive" in device_class:
        return "HIGH"

    return "LOW"


# ==========================================================
# MAIN MONITOR THREAD
# ==========================================================

def start_usb_monitor(send_event_callback):
    if not _is_windows():
        print("[USB] Advanced monitor skipped (Windows only)")
        return

    import pythoncom

    print("[USB] Advanced monitor starting...")

    pythoncom.CoInitialize()

    while True:
        try:
            enumerate_usb_devices()
            mounts = detect_usb_mounts()

            # -----------------------------------
            # If no storage mounted
            # -----------------------------------
            if not mounts:
                event = {
                    "event_type": "USB_REALTIME",
                    "mount": None,
                    "intel": None,
                    "risk": None,
                    "timestamp": time.time()
                }

                send_event_callback(event)
                time.sleep(SCAN_INTERVAL)
                continue

            # -----------------------------------
            # If storage present
            # -----------------------------------
            for mount in mounts:

                storage_intel = scan_storage(mount)

                event = {
                    "event_type": "USB_REALTIME",
                    "mount": mount,
                    "intel": storage_intel,
                    "risk": storage_intel["risk"],
                    "timestamp": time.time()
                }

                send_event_callback(event)

        except Exception as e:
            print("[USB ERROR]", e)

        time.sleep(SCAN_INTERVAL)
