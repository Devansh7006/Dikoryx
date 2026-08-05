"""
Re-exports from the canonical database module.

Prefer ``from backend.database import ...`` for new code.
This module exists for backward compatibility with legacy import paths.
"""

from backend.database import (
    Agent,
    AgentRecord,
    Base,
    DlpAlert,
    Event,
    Organization,
    RiskLog,
    SessionLocal,
    User,
    bulk_save_events,
    create_organization,
    engine,
    get_agent_by_api_key,
    get_dlp_alerts,
    get_organization_by_id,
    init_db,
    list_organizations,
    register_agent,
    save_dlp_alerts,
    save_event,
    save_risk_log,
    touch_agent_last_seen,
)

__all__ = [
    "Agent",
    "AgentRecord",
    "Base",
    "DlpAlert",
    "Event",
    "Organization",
    "RiskLog",
    "SessionLocal",
    "User",
    "bulk_save_events",
    "create_organization",
    "engine",
    "get_agent_by_api_key",
    "get_dlp_alerts",
    "get_organization_by_id",
    "init_db",
    "list_organizations",
    "register_agent",
    "save_dlp_alerts",
    "save_event",
    "save_risk_log",
    "touch_agent_last_seen",
]
