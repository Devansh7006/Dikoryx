import hashlib
import json
import os
import socket
import uuid
import platform
from typing import Any, cast

try:
    import winreg
except ImportError:
    winreg = None

IDENTITY_FILE = os.environ.get("ITD_IDENTITY_FILE", "agent_identity.json")


def get_machine_guid() -> str:
    if not winreg:
        return "unknown-guid"

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        )

        guid, _ = winreg.QueryValueEx(
            key,
            "MachineGuid"
        )

        return str(guid)

    except Exception:
        return "unknown-guid"


def get_device_fingerprint() -> str:
    hostname = socket.gethostname()
    mac = hex(uuid.getnode())
    machine_guid = get_machine_guid()
    os_name = platform.system()

    raw = f"{machine_guid}|{hostname}|{mac}|{os_name}"

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


def save_identity(identity: dict[str, Any], path: str | None = None) -> dict[str, Any]:
    """Persist identity data to disk."""
    target = path or IDENTITY_FILE
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(identity, handle)
    return identity


def load_or_create_identity(path: str | None = None) -> dict[str, Any]:
    """Load identity from disk or create a new local agent identity."""
    target = path or IDENTITY_FILE
    if os.path.exists(target):
        with open(target, encoding="utf-8") as handle:
            return cast(dict[str, Any], json.load(handle))

    identity = {
        "agent_id": str(uuid.uuid4()),
        "fingerprint": get_device_fingerprint(),
    }
    save_identity(identity, path=target)
    return identity
