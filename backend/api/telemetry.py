import time
from typing import Optional

from fastapi import APIRouter, Depends

from backend.agent_auth import AuthenticatedAgent, get_current_agent, resolve_agent_id
from backend.database import PendingEvent, SessionLocal, bulk_save_events, save_dlp_alerts
from backend.dlp_engine import evaluate_dlp
from backend.perf import ingest_request_scope, log_perf, perf_counter
from backend.state import events, systems

router = APIRouter(tags=["Telemetry"])

_COMPLIANCE_TYPES = {"COMPLIANCE_STATUS", "COMPLIANCE_EVENT"}


def _default_system(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "username": None,
        "last_seen": None,
        "os": {},
        "usb": {},
        "vpn": {},
        "compliance": None,
        "auth": {
            "logins": 0,
            "last_user": None,
        },
    }


@router.post(
    "/api/v1/ingest",
    summary="Ingest agent events",
    description=(
        "Accept batched telemetry from an endpoint agent. "
        "When `REQUIRE_AGENT_AUTH=true`, send `Authorization: Bearer <api_key>`."
    ),
    responses={
        401: {"description": "Missing or invalid API key"},
    },
)
async def ingest(
    payload: dict,
    agent: Optional[AuthenticatedAgent] = Depends(get_current_agent),
) -> dict:
    with ingest_request_scope():
        total_start = perf_counter()
        parse_start = perf_counter()

        agent_id = resolve_agent_id(payload, agent)
        evs = payload.get("events", [])

        system = systems.setdefault(agent_id, _default_system(agent_id))

        system["last_seen"] = time.time()
        events.setdefault(agent_id, [])

        pending_events: list[PendingEvent] = []
        for ev in evs:
            ev["received_at"] = time.time()
            events[agent_id].append(ev)
            pending_events.append(
                {
                    "agent_id": agent_id,
                    "event_type": ev.get("event_type"),
                    "data": ev,
                }
            )

            if ev.get("os"):
                system["os"] = ev.get("os")
                u = ev.get("os", {}).get("username")
                if u:
                    system["username"] = u

            event_type = (ev.get("event_type") or "").upper()

            if event_type.startswith("USB") and event_type != "USB_REMOVE":
                system["usb"] = {
                    "mount": ev.get("mount"),
                    "intel": ev.get("intel"),
                    "risk": ev.get("risk"),
                    "last_event": ev.get("event_type"),
                    "timestamp": ev.get("timestamp"),
                }
            elif event_type == "USB_REMOVE":
                system["usb"] = {
                    "mount": ev.get("mount"),
                    "status": "removed",
                    "timestamp": ev.get("timestamp"),
                }
            elif event_type == "VPN_EVENT":
                system["vpn"] = ev.get("vpn_info", {})
            elif event_type == "USER_LOGIN":
                system["auth"]["logins"] += 1
                system["auth"]["last_user"] = ev.get("username")
            elif event_type in _COMPLIANCE_TYPES:
                system["compliance"] = {
                    "controls": ev.get("controls") or {},
                    "compliance_score": ev.get("compliance_score"),
                    "enforced": ev.get("enforced") or [],
                    "timestamp": ev.get("timestamp") or time.time(),
                }

        log_perf("request_parsing", perf_counter() - parse_start)

        bulk_start = perf_counter()
        if pending_events:
            session = SessionLocal()
            try:
                bulk_save_events(pending_events, session=session, commit=False)
                session.commit()
            except Exception as e:
                session.rollback()
                print("[DB ERROR]", e)
            finally:
                session.close()
        log_perf("bulk_save_events", perf_counter() - bulk_start)

        active_dlp = evaluate_dlp(agent_id, events[agent_id], system)
        if active_dlp:
            save_dlp_alerts(agent_id, active_dlp)

        log_perf("total_ingest", perf_counter() - total_start)
        return {"status": "ok", "received": len(evs)}


async def _heartbeat(
    payload: dict,
    agent: Optional[AuthenticatedAgent],
) -> dict:
    agent_id = resolve_agent_id(payload, agent)

    system = systems.setdefault(agent_id, _default_system(agent_id))
    system["last_seen"] = time.time()
    system["os"] = payload.get("os", {})

    username = (payload.get("os") or {}).get("username")
    if username:
        system["username"] = username

    return {"status": "alive"}


@router.post(
    "/api/v1/ingest/heartbeat",
    summary="Agent heartbeat (legacy path)",
    description=(
        "Heartbeat used by existing agents at `/api/v1/ingest/heartbeat`. "
        "When `REQUIRE_AGENT_AUTH=true`, send `Authorization: Bearer <api_key>`."
    ),
    responses={
        401: {"description": "Missing or invalid API key"},
    },
)
async def heartbeat_legacy(
    payload: dict,
    agent: Optional[AuthenticatedAgent] = Depends(get_current_agent),
) -> dict:
    return await _heartbeat(payload, agent)


@router.post(
    "/api/v1/heartbeat",
    summary="Agent heartbeat",
    description=(
        "Report agent liveness. When `REQUIRE_AGENT_AUTH=true`, "
        "send `Authorization: Bearer <api_key>`."
    ),
    responses={
        401: {"description": "Missing or invalid API key"},
    },
)
async def heartbeat(
    payload: dict,
    agent: Optional[AuthenticatedAgent] = Depends(get_current_agent),
) -> dict:
    return await _heartbeat(payload, agent)
