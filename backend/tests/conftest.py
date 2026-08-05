from collections.abc import Callable, Generator
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.state import events, systems


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def clear_runtime_state() -> Generator[None, None, None]:
    systems.clear()
    events.clear()
    yield
    systems.clear()
    events.clear()


@pytest.fixture(autouse=True)
def reset_risk_engine_state() -> Generator[None, None, None]:
    from backend import risk_engine

    risk_engine.AGENT_HISTORY.clear()
    risk_engine.AGENT_MODELS.clear()
    yield
    risk_engine.AGENT_HISTORY.clear()
    risk_engine.AGENT_MODELS.clear()


@pytest.fixture
def now_ts() -> float:
    import time

    return time.time()


@pytest.fixture
def make_user() -> Callable[..., MagicMock]:
    def _factory(
        *,
        agent_id: str = "agent-user1",
        username: str = "alice",
        password_hash: str | None = "hashed",
        name: str = "Alice",
        department: str = "Engineering",
        photo_url: str = "http://example.com/a.jpg",
    ) -> MagicMock:
        user = MagicMock()
        user.agent_id = agent_id
        user.username = username
        user.password_hash = password_hash
        user.name = name
        user.department = department
        user.photo_url = photo_url
        return user

    return _factory


@pytest.fixture
def make_org_record() -> Callable[..., dict]:
    def _factory(
        *,
        org_id: int = 1,
        name: str = "Acme Corp",
        enrollment_token: str = "enroll-token",
    ) -> dict:
        return {
            "id": org_id,
            "name": name,
            "enrollment_token": enrollment_token,
            "created_at": datetime(2026, 1, 1, 12, 0, 0),
        }

    return _factory
