from fastapi import APIRouter, HTTPException

from backend.database import (
    OrganizationIdNotFoundError,
    create_organization,
    get_organization_by_id,
    list_organizations,
)
from backend.schemas.organizations import OrganizationCreateRequest, OrganizationResponse

router = APIRouter(tags=["Organizations"])


@router.post(
    "/api/v1/organizations",
    response_model=OrganizationResponse,
    status_code=201,
    summary="Create organization",
    description=(
        "Create a tenant organization. An enrollment token is generated automatically "
        "and returned in the response for agent onboarding."
    ),
)
def create_organization_endpoint(
    payload: OrganizationCreateRequest,
) -> OrganizationResponse:
    record = create_organization(payload.name)
    return OrganizationResponse(**record)


@router.get(
    "/api/v1/organizations",
    response_model=list[OrganizationResponse],
    summary="List organizations",
    description="Return all tenant organizations registered in the platform.",
)
def list_organizations_endpoint() -> list[OrganizationResponse]:
    return [OrganizationResponse(**record) for record in list_organizations()]


@router.get(
    "/api/v1/organizations/{org_id}",
    response_model=OrganizationResponse,
    summary="Get organization",
    description="Return a single organization by numeric identifier.",
)
def get_organization_endpoint(org_id: int) -> OrganizationResponse:
    try:
        record = get_organization_by_id(org_id)
    except OrganizationIdNotFoundError:
        raise HTTPException(status_code=404, detail="Organization not found") from None
    return OrganizationResponse(**record)
