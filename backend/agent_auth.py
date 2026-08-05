from typing import Optional, TypedDict

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend import config
from backend.database import AgentRecord, get_agent_by_api_key, touch_agent_last_seen

bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="AgentAPIKey",
    description=(
        "Agent API key from POST /api/v1/agents/register. "
        "Format: `Authorization: Bearer <api_key>`"
    ),
)


class AuthenticatedAgent(TypedDict):
    agent_id: str
    organization_id: int
    hostname: Optional[str]
    os: Optional[str]
    api_key: str


def _record_to_authenticated(record: AgentRecord) -> AuthenticatedAgent:
    return AuthenticatedAgent(
        agent_id=record["agent_id"],
        organization_id=record["organization_id"],
        hostname=record.get("hostname"),
        os=record.get("os"),
        api_key=record["api_key"],
    )


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_agent(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> Optional[AuthenticatedAgent]:
    """
    Validate agent API key when REQUIRE_AGENT_AUTH is enabled.

    Returns the authenticated agent record, or None when auth is disabled
    and no valid bearer token was supplied.
    """
    api_key: str | None = None
    if credentials is not None:
        api_key = credentials.credentials.strip() or None

    if not config.REQUIRE_AGENT_AUTH:
        if not api_key:
            return None
        record = get_agent_by_api_key(api_key)
        if record is None:
            return None
        touch_agent_last_seen(record["agent_id"])
        return _record_to_authenticated(record)

    if not api_key:
        raise _unauthorized()

    record = get_agent_by_api_key(api_key)
    if record is None:
        raise _unauthorized()

    touch_agent_last_seen(record["agent_id"])
    return _record_to_authenticated(record)


def resolve_agent_id(payload: dict, agent: Optional[AuthenticatedAgent]) -> str:
    """Use authenticated agent id when auth is enforced; otherwise payload agent_id."""
    if config.REQUIRE_AGENT_AUTH:
        if agent is None:
            raise _unauthorized()
        return agent["agent_id"]

    raw = payload.get("agent_id")
    if not raw or not isinstance(raw, str):
        raise HTTPException(status_code=400, detail="agent_id is required")
    return str(raw)
