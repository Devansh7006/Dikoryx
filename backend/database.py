import os
import secrets
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, TypedDict

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    Text,
    TIMESTAMP,
    create_engine,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from dotenv import load_dotenv

# ---------------- ENV ----------------

load_dotenv(dotenv_path=Path(__file__).parent / ".env")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./test.db"
)
if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set")

# ---------------- DB ENGINE ----------------

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

class Base(DeclarativeBase):
    pass

# ---------------- MODELS ----------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(Text, unique=True, index=True)
    password_hash = Column(Text)

    # ✅ ADD THESE (properly inside class)
    name = Column(Text)
    email = Column(Text)
    department = Column(Text)
    photo_url = Column(Text)

    agent_id = Column(Text, unique=True, default=lambda: f"agent-{uuid.uuid4().hex[:8]}")
    created_at = Column(TIMESTAMP, default=datetime.utcnow)

class LoginLog(Base):
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    username = Column(Text)
    login_time = Column(TIMESTAMP, default=datetime.utcnow)
    ip_address = Column(Text)
    user_agent = Column(Text)

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Text)
    event_type = Column(Text)
    data = Column(JSON)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)


class RiskLog(Base):
    __tablename__ = "risk_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Text)
    risk_score = Column(Integer)
    risk_level = Column(Text)
    reasons = Column(JSON)
    signals = Column(JSON)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)


class DlpAlert(Base):
    __tablename__ = "dlp_alerts"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Text, index=True)
    alert_type = Column(Text)
    severity = Column(Text)
    reason = Column(Text)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(Text, nullable=False)
    enrollment_token = Column(Text, unique=True, nullable=False, index=True)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)


class Agent(Base):
    __tablename__ = "agents"

    agent_id = Column(Text, primary_key=True)
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    hostname = Column(Text)
    os = Column(Text)
    last_seen = Column(TIMESTAMP, nullable=True)
    api_key = Column(Text, unique=True, nullable=False, index=True)


class AgentRegistrationResult(TypedDict):
    agent_id: str
    api_key: str


class AgentRecord(TypedDict):
    agent_id: str
    organization_id: int
    hostname: str | None
    os: str | None
    api_key: str


class OrganizationNotFoundError(Exception):
    """Raised when enrollment_token does not match any organization."""


class OrganizationIdNotFoundError(Exception):
    """Raised when organization id does not exist."""


class OrganizationRecord(TypedDict):
    id: int
    name: str
    enrollment_token: str
    created_at: datetime


# ---------------- INIT ----------------

def init_db():
    Base.metadata.create_all(bind=engine)

# ---------------- SAVE EVENT ----------------

class PendingEvent(TypedDict):
    agent_id: str
    event_type: str | None
    data: dict[str, Any]


def _should_commit(commit: bool | None, owns_session: bool) -> bool:
    if commit is not None:
        return commit
    return owns_session


def bulk_save_events(
    records: list[PendingEvent],
    *,
    session: Session | None = None,
    commit: bool | None = None,
) -> None:
    """Insert multiple events in one session; commits once when owning the session."""
    if not records:
        return

    owns_session = session is None
    db = session or SessionLocal()
    try:
        db.add_all(
            Event(
                agent_id=record["agent_id"],
                event_type=record["event_type"],
                data=record["data"],
            )
            for record in records
        )
        if _should_commit(commit, owns_session):
            db.commit()
    except Exception as e:
        db.rollback()
        print("[DB ERROR]", e)
    finally:
        if owns_session:
            db.close()


def save_event(
    agent_id: str,
    event_type: str | None,
    data: dict[str, Any],
    *,
    session: Session | None = None,
    commit: bool | None = None,
) -> None:
    bulk_save_events(
        [{"agent_id": agent_id, "event_type": event_type, "data": data}],
        session=session,
        commit=commit,
    )


# ---------------- SAVE RISK LOG ----------------

def save_risk_log(
    agent_id: str,
    risk_score: int,
    risk_level: str,
    reasons: Any,
    signals: Any,
    *,
    session: Session | None = None,
    commit: bool | None = None,
) -> None:
    owns_session = session is None
    db = session or SessionLocal()
    try:
        log = RiskLog(
            agent_id=agent_id,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=reasons,
            signals=signals,
        )
        db.add(log)
        if _should_commit(commit, owns_session):
            db.commit()
    except Exception as e:
        db.rollback()
        print("[RISK LOG ERROR]", e)
    finally:
        if owns_session:
            db.close()


# ---------------- DLP ALERTS ----------------

DLP_DEDUP_SECONDS = 300


def save_dlp_alerts(agent_id: str, alerts: list) -> int:
    """Persist new DLP alerts, skipping duplicates of the same type+severity within dedup window."""
    if not alerts:
        return 0

    session = SessionLocal()
    saved = 0
    try:
        cutoff = datetime.utcfromtimestamp(time.time() - DLP_DEDUP_SECONDS)

        for alert in alerts:
            alert_type = alert.get("type")
            severity = alert.get("severity")
            reason = alert.get("reason")
            if not alert_type or not severity:
                continue

            recent = (
                session.query(DlpAlert)
                .filter(
                    DlpAlert.agent_id == agent_id,
                    DlpAlert.alert_type == alert_type,
                    DlpAlert.severity == severity,
                    DlpAlert.created_at >= cutoff,
                )
                .first()
            )
            if recent:
                continue

            row = DlpAlert(
                agent_id=agent_id,
                alert_type=alert_type,
                severity=severity,
                reason=reason,
            )
            session.add(row)
            saved += 1

        if saved:
            session.commit()
    except Exception as e:
        session.rollback()
        print("[DLP ALERT ERROR]", e)
    finally:
        session.close()

    return saved


def get_dlp_alerts(agent_id=None, limit: int = 100) -> list:
    session = SessionLocal()
    try:
        q = session.query(DlpAlert).order_by(DlpAlert.created_at.desc())
        if agent_id:
            q = q.filter(DlpAlert.agent_id == agent_id)
        rows = q.limit(limit).all()
        return [
            {
                "id": row.id,
                "agent_id": row.agent_id,
                "type": row.alert_type,
                "severity": row.severity,
                "reason": row.reason,
                "timestamp": row.created_at.timestamp() if row.created_at else None,
            }
            for row in rows
        ]
    finally:
        session.close()


# ---------------- AGENT LOOKUP ----------------

def _agent_record(agent: Agent) -> AgentRecord:
    return AgentRecord(
        agent_id=str(agent.agent_id),
        organization_id=int(agent.organization_id),
        hostname=str(agent.hostname) if agent.hostname is not None else None,
        os=str(agent.os) if agent.os is not None else None,
        api_key=str(agent.api_key),
    )


def get_agent_by_api_key(api_key: str) -> Optional[AgentRecord]:
    session = SessionLocal()
    try:
        agent = session.query(Agent).filter(Agent.api_key == api_key).first()
        if agent is None:
            return None
        return _agent_record(agent)
    finally:
        session.close()


def touch_agent_last_seen(agent_id: str) -> None:
    session = SessionLocal()
    try:
        agent = session.query(Agent).filter(Agent.agent_id == agent_id).first()
        if agent is None:
            return
        agent.last_seen = datetime.utcnow()  # type: ignore[assignment]
        session.commit()
    except Exception as e:
        session.rollback()
        print("[AGENT TOUCH ERROR]", e)
    finally:
        session.close()


# ---------------- AGENT REGISTRATION ----------------

def _new_agent_id() -> str:
    return f"agent-{uuid.uuid4().hex[:12]}"


def _new_api_key() -> str:
    return secrets.token_urlsafe(32)


def _new_enrollment_token() -> str:
    return secrets.token_urlsafe(32)


def _organization_record(org: Organization) -> OrganizationRecord:
    created_at_raw = org.created_at
    created_at = (
        created_at_raw if isinstance(created_at_raw, datetime) else datetime.utcnow()
    )
    return OrganizationRecord(
        id=int(org.id),
        name=str(org.name),
        enrollment_token=str(org.enrollment_token),
        created_at=created_at,
    )


def create_organization(name: str) -> OrganizationRecord:
    session = SessionLocal()
    try:
        org = Organization(
            name=name,
            enrollment_token=_new_enrollment_token(),
        )
        session.add(org)
        session.commit()
        session.refresh(org)
        return _organization_record(org)
    except Exception as e:
        session.rollback()
        print("[ORG CREATE ERROR]", e)
        raise
    finally:
        session.close()


def list_organizations() -> list[OrganizationRecord]:
    session = SessionLocal()
    try:
        rows = session.query(Organization).order_by(Organization.id.asc()).all()
        return [_organization_record(row) for row in rows]
    finally:
        session.close()


def get_organization_by_id(org_id: int) -> OrganizationRecord:
    session = SessionLocal()
    try:
        org = session.query(Organization).filter(Organization.id == org_id).first()
        if org is None:
            raise OrganizationIdNotFoundError(f"Organization {org_id} not found")
        return _organization_record(org)
    finally:
        session.close()


def register_agent(
    enrollment_token: str,
    hostname: str,
    os_name: str,
) -> AgentRegistrationResult:
    """Register a new agent under the organization matching enrollment_token."""
    session = SessionLocal()
    try:
        organization = (
            session.query(Organization)
            .filter(Organization.enrollment_token == enrollment_token)
            .first()
        )
        if organization is None:
            raise OrganizationNotFoundError("Invalid enrollment token")

        now = datetime.utcnow()
        agent = Agent(
            agent_id=_new_agent_id(),
            organization_id=organization.id,
            hostname=hostname,
            os=os_name,
            last_seen=now,
            api_key=_new_api_key(),
        )
        session.add(agent)
        session.commit()
        session.refresh(agent)
        agent_id = str(agent.agent_id)
        api_key = str(agent.api_key)
        return AgentRegistrationResult(
            agent_id=agent_id,
            api_key=api_key,
        )
    except OrganizationNotFoundError:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        print("[AGENT REGISTER ERROR]", e)
        raise
    finally:
        session.close()