"""Realistic telemetry payload generators for Dikoryx load testing."""

from __future__ import annotations

import random
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

HOSTNAME_PREFIXES: tuple[str, ...] = ("ws", "laptop", "desktop", "vm", "dev")
PROCESS_NAMES: tuple[str, ...] = (
    "chrome.exe",
    "outlook.exe",
    "explorer.exe",
    "teams.exe",
    "powershell.exe",
    "excel.exe",
    "winword.exe",
    "notepad.exe",
)
SENSITIVE_FILES: tuple[str, ...] = (
    "salary.csv",
    "payroll.xlsx",
    "finance_report.pdf",
    "customer_list.xlsx",
    "employee_records.docx",
    "confidential_invoice.pdf",
    "bank_statement.csv",
)
USB_DRIVES: tuple[str, ...] = ("E:\\", "F:\\", "G:\\", "H:\\")
SEVERITIES: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")

EventGenerator = Callable[[], dict[str, Any]]


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    hostname: str
    fingerprint: str
    session_id: str


def random_agent_id() -> str:
    return str(uuid.uuid4())


def random_hostname() -> str:
    prefix = random.choice(HOSTNAME_PREFIXES)
    suffix = random.randint(1000, 99999)
    return f"{prefix}-{suffix}.corp.local"


def random_timestamp(max_age_seconds: float = 300.0) -> float:
    return time.time() - random.uniform(0, max_age_seconds)


def create_agent_identity(
    *,
    agent_id: str | None = None,
    hostname: str | None = None,
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id or random_agent_id(),
        hostname=hostname or random_hostname(),
        fingerprint=str(uuid.uuid4()),
        session_id=str(uuid.uuid4()),
    )


def generate_os_info(hostname: str) -> dict[str, Any]:
    return {
        "os": "Windows",
        "version": "10.0.26200",
        "username": f"user{random.randint(1, 500)}",
        "hostname": hostname,
    }


def generate_heartbeat_payload(identity: AgentIdentity) -> dict[str, Any]:
    return {
        "agent_id": identity.agent_id,
        "fingerprint": identity.fingerprint,
        "session_id": identity.session_id,
        "timestamp": random_timestamp(),
        "hostname": identity.hostname,
        "os": generate_os_info(identity.hostname),
    }


def generate_file_activity_event() -> dict[str, Any]:
    write_count = random.randint(1, 250)
    delete_count = random.randint(0, 40)
    rename_count = random.randint(0, 20)
    total = write_count + delete_count + rename_count
    summary: dict[str, Any] = {
        "write": write_count,
        "delete": delete_count,
        "rename": rename_count,
    }
    if random.random() < 0.25:
        sample_size = random.randint(1, 5)
        summary["sensitive_files"] = random.sample(
            list(SENSITIVE_FILES),
            k=min(sample_size, len(SENSITIVE_FILES)),
        )
    return {
        "event_type": "FILE_ACTIVITY_SUMMARY",
        "summary": summary,
        "severity": _severity_for_total(total, low=50, medium=200),
        "timestamp": random_timestamp(),
    }


def generate_process_event() -> dict[str, Any]:
    process_count = random.randint(3, len(PROCESS_NAMES))
    summary = {
        name: random.randint(1, 15)
        for name in random.sample(list(PROCESS_NAMES), k=process_count)
    }
    total = sum(summary.values())
    return {
        "event_type": "PROCESS_ACTIVITY_SUMMARY",
        "summary": summary,
        "severity": _severity_for_total(total, low=20, medium=50),
        "timestamp": random_timestamp(),
    }


def generate_usb_event() -> dict[str, Any]:
    variant = random.choice(("realtime_insert", "realtime_remove", "usb_event", "usb_remove"))
    drive = random.choice(USB_DRIVES)
    timestamp = random_timestamp()

    if variant == "realtime_insert":
        return {
            "event_type": "USB_REALTIME",
            "drive": drive,
            "mount": drive,
            "action": "inserted",
            "intel": {
                "risk": random.choice(SEVERITIES),
                "suspicious_files": random.sample(
                    list(SENSITIVE_FILES),
                    k=random.randint(0, 2),
                ),
            },
            "timestamp": timestamp,
        }
    if variant == "realtime_remove":
        return {
            "event_type": "USB_REALTIME",
            "drive": drive,
            "mount": drive,
            "action": "removed",
            "timestamp": timestamp,
        }
    if variant == "usb_remove":
        return {
            "event_type": "USB_REMOVE",
            "mount": drive,
            "timestamp": timestamp,
        }
    return {
        "event_type": "USB_EVENT",
        "mount": drive,
        "fingerprint": str(uuid.uuid4()),
        "summary": {
            "total_files": random.randint(10, 5000),
            "added": random.randint(0, 50),
            "removed": random.randint(0, 20),
            "modified": random.randint(0, 30),
        },
        "timestamp": timestamp,
    }


def generate_dlp_event() -> dict[str, Any]:
    """Emit collector events that commonly trigger server-side DLP evaluation."""
    variant = random.choice(("clipboard_spike", "sensitive_file_access", "usb_exfil_pattern"))
    timestamp = random_timestamp()

    if variant == "clipboard_spike":
        return {
            "event_type": "CLIPBOARD_ACTIVITY_SUMMARY",
            "summary": {
                "copy_events": random.randint(21, 60),
                "paste_events": random.randint(0, 10),
            },
            "severity": "HIGH",
            "timestamp": timestamp,
        }
    if variant == "sensitive_file_access":
        return {
            "event_type": "FILE_ACTIVITY_SUMMARY",
            "summary": {
                "write": random.randint(5, 40),
                "sensitive_files": random.sample(
                    list(SENSITIVE_FILES),
                    k=random.randint(1, 3),
                ),
            },
            "severity": "HIGH",
            "timestamp": timestamp,
        }
    return {
        "event_type": "FILE_ACTIVITY_SUMMARY",
        "summary": {
            "write": random.randint(30, 80),
            "delete": random.randint(10, 30),
            "rename": random.randint(5, 15),
        },
        "severity": "HIGH",
        "timestamp": timestamp,
    }


EVENT_GENERATORS: dict[str, EventGenerator] = {
    "file_activity": generate_file_activity_event,
    "process": generate_process_event,
    "usb": generate_usb_event,
    "dlp": generate_dlp_event,
}


def generate_telemetry_batch(
    identity: AgentIdentity,
    *,
    min_events: int = 2,
    max_events: int = 6,
) -> dict[str, Any]:
    count = random.randint(min_events, max_events)
    generators = list(EVENT_GENERATORS.values())
    events = [random.choice(generators)() for _ in range(count)]
    return {
        "agent_id": identity.agent_id,
        "fingerprint": identity.fingerprint,
        "session_id": identity.session_id,
        "events": events,
    }


def _severity_for_total(total: int, *, low: int, medium: int) -> str:
    if total > medium:
        return "HIGH"
    if total > low:
        return "MEDIUM"
    return "LOW"
