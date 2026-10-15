from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class OrganizationCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, description="Display name for the tenant organization")


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique organization identifier")
    name: str = Field(..., description="Organization display name")
    enrollment_token: str = Field(
        ...,
        description="Token used by agents during POST /api/v1/agents/register",
    )
    created_at: datetime = Field(..., description="UTC timestamp when the organization was created")
