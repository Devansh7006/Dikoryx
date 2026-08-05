"""Tests for bulk event persistence."""

from __future__ import annotations

from typing import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.database import (
    Base,
    Event,
    PendingEvent,
    RiskLog,
    bulk_save_events,
    save_event,
    save_risk_log,
)


@pytest.fixture
def db_session(monkeypatch: pytest.MonkeyPatch) -> Generator[Session, None, None]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr("backend.database.SessionLocal", session_factory)
    session = session_factory()
    yield session
    session.close()


def _records(agent_id: str, count: int) -> list[PendingEvent]:
    return [
        {
            "agent_id": agent_id,
            "event_type": f"EVENT_{index}",
            "data": {"index": index},
        }
        for index in range(count)
    ]


class TestBulkSaveEvents:
    def test_bulk_save_events_inserts_all_rows(self, db_session: Session) -> None:
        bulk_save_events(_records("agent-bulk", 3), session=db_session, commit=False)
        db_session.commit()

        rows = db_session.query(Event).order_by(Event.id.asc()).all()
        assert len(rows) == 3
        assert [row.event_type for row in rows] == ["EVENT_0", "EVENT_1", "EVENT_2"]
        assert all(row.agent_id == "agent-bulk" for row in rows)

    def test_bulk_save_events_empty_list_is_noop(self, db_session: Session) -> None:
        bulk_save_events([], session=db_session, commit=False)
        db_session.commit()

        assert db_session.query(Event).count() == 0

    def test_bulk_save_events_defers_commit_when_session_provided(
        self,
        db_session: Session,
    ) -> None:
        bulk_save_events(_records("agent-defer", 2), session=db_session, commit=False)

        assert len(db_session.new) == 2
        db_session.rollback()
        assert db_session.query(Event).count() == 0

    def test_bulk_save_events_commits_when_owning_session(
        self,
        db_session: Session,
    ) -> None:
        bulk_save_events(_records("agent-own", 2))

        assert db_session.query(Event).count() == 2

    def test_save_event_still_persists_single_row(self, db_session: Session) -> None:
        save_event("agent-single", "HEARTBEAT", {"status": "alive"})

        rows = db_session.query(Event).all()
        assert len(rows) == 1
        assert rows[0].event_type == "HEARTBEAT"
        assert rows[0].data == {"status": "alive"}


class TestSharedSessionRiskLog:
    def test_save_risk_log_reuses_session_without_commit(
        self,
        db_session: Session,
    ) -> None:
        bulk_save_events(_records("agent-risk", 1), session=db_session, commit=False)
        save_risk_log(
            agent_id="agent-risk",
            risk_score=42,
            risk_level="MEDIUM",
            reasons=["test"],
            signals={"usb": True},
            session=db_session,
            commit=False,
        )

        assert len(db_session.new) == 2
        db_session.rollback()
        assert db_session.query(Event).count() == 0
        assert db_session.query(RiskLog).count() == 0

    def test_events_and_risk_log_commit_together(self, db_session: Session) -> None:
        bulk_save_events(_records("agent-commit", 2), session=db_session, commit=False)
        save_risk_log(
            agent_id="agent-commit",
            risk_score=80,
            risk_level="HIGH",
            reasons=["combined"],
            signals={},
            session=db_session,
            commit=False,
        )
        db_session.commit()

        assert db_session.query(Event).count() == 2
        risk_rows = db_session.query(RiskLog).all()
        assert len(risk_rows) == 1
        assert risk_rows[0].risk_score == 80
