from fastapi import APIRouter
from typing import Dict, Any, List
import time

from backend.risk_engine import compute_risk
from backend.database import PendingEvent, SessionLocal, bulk_save_events, save_risk_log
from backend.perf import ingest_request_scope, log_perf, perf_counter

router = APIRouter()
print("INGEST API CALLED")

# In-memory system state
SYSTEM_STATE: Dict[str, Dict[str, Any]] = {}


@router.post("/api/v1/ingest")
async def ingest_events(payload: Dict[str, Any]):
    with ingest_request_scope():
        total_start = perf_counter()
        parse_start = perf_counter()

        agent_id = payload.get("agent_id")
        print("INGEST HIT", agent_id)
        events: List[Dict[str, Any]] = payload.get("events", [])

        if not agent_id:
            log_perf("request_parsing", perf_counter() - parse_start)
            log_perf("bulk_save_events", 0.0)
            log_perf("compute_risk", 0.0)
            log_perf("save_risk_log", 0.0)
            log_perf("total_ingest", perf_counter() - total_start)
            return {"status": "error", "reason": "agent_id missing"}

        system = SYSTEM_STATE.setdefault(agent_id, {
            "agent_id": agent_id,
            "last_seen": None,
            "usb": {},
            "vpn": {},
            "auth": {"logins": 0, "last_user": None},
            "events": []
        })

        system["last_seen"] = time.time()
        system["os"] = payload.get("os", {})

        pending_events: list[PendingEvent] = [
            {"agent_id": agent_id, "event_type": "HEARTBEAT", "data": payload},
        ]

        for event in events:
            event_type = event.get("event_type") or "UNKNOWN"

            # Store in memory
            system["events"].append(event)

            pending_events.append(
                {"agent_id": agent_id, "event_type": event_type, "data": event}
            )

            # ---------- AUTH ----------
            if event_type == "USER_LOGIN":
                system["auth"]["logins"] += 1
                system["auth"]["last_user"] = event.get("username")

            # ---------- VPN ----------
            elif event_type == "VPN_EVENT":
                system["vpn"] = event.get("vpn_info", {})

            # ---------- USB ----------
            elif event_type == "USB_EVENT":
                system["usb"] = {
                    "mount": event.get("mount"),
                    "summary": event.get("summary"),
                    "last_seen": event.get("timestamp")
                }

        log_perf("request_parsing", perf_counter() - parse_start)

        risk_start = perf_counter()
        risk = compute_risk(agent_id, system["events"], system)
        log_perf("compute_risk", perf_counter() - risk_start)

        session = SessionLocal()
        try:
            bulk_start = perf_counter()
            bulk_save_events(pending_events, session=session, commit=False)
            log_perf("bulk_save_events", perf_counter() - bulk_start)

            risk_log_start = perf_counter()
            save_risk_log(
                agent_id=risk["agent_id"],
                risk_score=risk["risk_score"],
                risk_level=risk["risk_level"],
                reasons=risk["reasons"],
                signals=risk.get("signals", {}),
                session=session,
                commit=False,
            )
            log_perf("save_risk_log", perf_counter() - risk_log_start)

            session.commit()
        except Exception as e:
            session.rollback()
            print("[INGEST DB ERROR]", e)
        finally:
            session.close()

        log_perf("total_ingest", perf_counter() - total_start)
        return {
            "status": "ok",
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"]
        }


@router.get("/api/v1/system/{agent_id}")
async def get_system(agent_id: str):
    system = SYSTEM_STATE.get(agent_id)

    if not system:
        return {"error": "agent not found"}

    return system