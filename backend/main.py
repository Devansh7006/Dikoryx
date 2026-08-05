import sys
import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend import config
from backend.api import agents, auth, organizations, telemetry
from backend.database import (
    get_dlp_alerts,
    init_db,
    save_dlp_alerts,
    save_risk_log,
)
from backend.dlp_engine import evaluate_dlp
from backend.risk_engine import compute_risk
from backend.state import events, systems

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

app = FastAPI(
    title="Insider Threat Detection Backend",
    description=(
        "Dikoryx ITD API for insider threat detection, DLP alerts, and SaaS multi-tenancy. "
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
    active_dlp = evaluate_dlp(agent_id, agent_events, system or {})
    if active_dlp:
        save_dlp_alerts(agent_id, active_dlp)
    risk = compute_risk(agent_id, agent_events, system or {}, dlp_alerts=active_dlp)
    save_risk_log(
        agent_id=risk["agent_id"],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        reasons=risk["reasons"],
        signals=risk.get("signals", {}),
    )
    stored_dlp = get_dlp_alerts(agent_id, limit=50)
    return {
        "system": system,
        "events": list(agent_events),
        "risk_score": risk.get("risk_score"),
        "risk_level": risk.get("risk_level"),
        "risk_reasons": risk.get("reasons", []),
        "dlp_alerts": stored_dlp,
        "dlp_active": active_dlp,
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
    active_dlp = evaluate_dlp(agent_id, agent_events, system)
    return compute_risk(agent_id, agent_events, system, dlp_alerts=active_dlp)

@app.get("/api/v1/risk")
def get_all_risk():
    output = []
    for agent_id in systems:
        agent_events = events.get(agent_id, [])
        system = systems.get(agent_id, {})
        active_dlp = evaluate_dlp(agent_id, agent_events, system)
        output.append(compute_risk(agent_id, agent_events, system, dlp_alerts=active_dlp))
    return output


# ------------------ DLP APIs ------------------

@app.get("/api/v1/dlp/{agent_id}")
def get_agent_dlp_alerts(agent_id: str):
    agent_events = events.get(agent_id, [])
    system = systems.get(agent_id, {})
    active = evaluate_dlp(agent_id, agent_events, system or {})
    stored = get_dlp_alerts(agent_id, limit=100)
    return {"agent_id": agent_id, "active": active, "alerts": stored}


@app.get("/api/v1/dlp")
def get_all_dlp_alerts():
    stored = get_dlp_alerts(limit=200)
    active_by_agent = []
    for agent_id in systems:
        agent_events = events.get(agent_id, [])
        system = systems.get(agent_id, {})
        active = evaluate_dlp(agent_id, agent_events, system)
        if active:
            active_by_agent.append({"agent_id": agent_id, "active": active})
    return {"alerts": stored, "active_by_agent": active_by_agent}

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
            "compliance_score": (system.get("compliance") or {}).get("compliance_score"),
        })
    return {"systems": summary}
