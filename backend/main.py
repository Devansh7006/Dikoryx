import sys
import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend import config
from backend.api import agents, auth, organizations, telemetry
from backend.database import (
    init_db,
    save_risk_log,
    Event,
    SessionLocal,
)
from backend.risk_engine import compute_risk
from backend.state import events, systems

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

app = FastAPI(
    title="Insider Threat Detection Backend",
    description=(
        "Dikoryx ITD API for insider threat detection, and SaaS multi-tenancy. "
        "Use **Organizations** to create tenants and enrollment tokens, then **Agents** to register endpoints. "
        "Telemetry endpoints accept optional or required `Authorization: Bearer <api_key>` "
        f"(REQUIRE_AGENT_AUTH={'true' if config.REQUIRE_AGENT_AUTH else 'false'})."
    ),
    version="1.0.0",
)
init_db()

app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(agents.router)
app.include_router(telemetry.router)

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "dikoryx-backend"
    }

# ------------------ No Cache Middleware ------------------

async def no_cache_middleware(request, call_next):
    response = await call_next(request)
    if request.method == "GET":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response

app.middleware("http")(no_cache_middleware)

# ------------------ CORS ------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ READ APIs ------------------

@app.get("/api/v1/system/{agent_id}")
def get_system(agent_id: str):
    system = systems.get(agent_id)
    agent_events = events.get(agent_id, [])

    # Rehydrate from database if memory was cleared or vpn is missing
    session = SessionLocal()
    try:
        if not agent_events or not system or not (system and system.get("vpn")):
            db_evs = session.query(Event).filter(Event.agent_id == agent_id).order_by(Event.id.desc()).limit(150).all()
            if db_evs:
                if not agent_events:
                    agent_events = [ev.data for ev in reversed(db_evs) if isinstance(ev.data, dict)]
                    events[agent_id] = agent_events

                if system is None:
                    system = telemetry._default_system(agent_id)
                    systems[agent_id] = system

                if not system.get("vpn"):
                    for ev in db_evs:
                        if (ev.event_type or "").upper() == "VPN_EVENT" and isinstance(ev.data, dict):
                            system["vpn"] = ev.data.get("vpn_info", {})
                            break

                if not system.get("compliance"):
                    for ev in db_evs:
                        if (ev.event_type or "").upper() in ("COMPLIANCE_STATUS", "COMPLIANCE_EVENT") and isinstance(ev.data, dict):
                            system["compliance"] = {
                                "controls": ev.data.get("controls") or {},
                                "compliance_score": ev.data.get("compliance_score"),
                                "enforced": ev.data.get("enforced") or [],
                                "timestamp": ev.data.get("timestamp") or time.time(),
                            }
                            break
    except Exception as e:
        print("[DB HYDRATE ERROR]", e)
    finally:
        session.close()

    risk = compute_risk(agent_id, agent_events, system or {})

    save_risk_log(
        agent_id=risk["agent_id"],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        reasons=risk["reasons"],
        signals=risk.get("signals", {}),
    )

    return {
        "system": system,
        "events": list(agent_events),
        "risk_score": risk.get("risk_score"),
        "risk_level": risk.get("risk_level"),
        "risk_reasons": risk.get("reasons", [])
    }

@app.get("/api/v1/systems")
def get_all_systems():
    now = time.time()
    TIMEOUT = 30  # seconds

    active_systems = []

    for system in systems.values():
        last = system.get("last_seen", 0)

        # mark active/inactive
        system["active"] = (now - last) < TIMEOUT

        # only return active agents
        if system["active"]:
            active_systems.append(system)

    return active_systems

# ------------------ Risk Engine ------------------

@app.get("/api/v1/risk/{agent_id}")
def get_risk(agent_id: str):
    agent_events = events.get(agent_id, [])
    system = systems.get(agent_id, {})
    
    return compute_risk(agent_id, agent_events, system)

@app.get("/api/v1/risk")
def get_all_risk():
    output = []
    for agent_id in systems:
        agent_events = events.get(agent_id, [])
        system = systems.get(agent_id, {})
        output.append(compute_risk(agent_id, agent_events, system))
    return output


# ------------------ Root Status ------------------

@app.get("/")
def root():
    summary = []
    for agent_id, system in systems.items():
        agent_events = events.get(agent_id, [])
        risk = compute_risk(agent_id, agent_events, system)
        summary.append({
            "agent_id": agent_id,
            "username": system.get("username") or (system.get("auth") or {}).get("last_user"),
            "last_seen": system.get("last_seen"),
            "events_count": len(agent_events),
            "risk": risk,
        })
    return {"systems": summary}
