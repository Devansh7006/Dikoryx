from fastapi import APIRouter, HTTPException

from backend.database import OrganizationNotFoundError, register_agent
from backend.schemas.agents import AgentRegisterRequest, AgentRegisterResponse

router = APIRouter(tags=["Agents"])


@router.post(
    "/api/v1/agents/register",
    response_model=AgentRegisterResponse,
    summary="Register agent",
    description="Enroll an endpoint using a valid organization enrollment token.",
)
def register_agent_endpoint(payload: AgentRegisterRequest) -> AgentRegisterResponse:
    try:
        result = register_agent(
            enrollment_token=payload.enrollment_token,
            hostname=payload.hostname,
            os_name=payload.os,
        )
    except OrganizationNotFoundError:
        raise HTTPException(status_code=404, detail="Invalid enrollment token") from None

    return AgentRegisterResponse(
        agent_id=result["agent_id"],
        api_key=result["api_key"],
    )
