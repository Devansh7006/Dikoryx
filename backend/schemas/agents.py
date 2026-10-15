from pydantic import BaseModel, Field


class AgentRegisterRequest(BaseModel):
    enrollment_token: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)
    os: str = Field(..., min_length=1)


class AgentRegisterResponse(BaseModel):
    agent_id: str
    api_key: str
