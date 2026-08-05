from unittest.mock import patch

from backend.database import OrganizationIdNotFoundError


class TestOrganizationsApi:
    @patch("backend.api.organizations.create_organization")
    def test_create_organization(self, mock_create, client, make_org_record) -> None:
        mock_create.return_value = make_org_record()
        response = client.post("/api/v1/organizations", json={"name": "Acme Corp"})
        assert response.status_code == 201
        body = response.json()
        assert body["name"] == "Acme Corp"
        assert body["enrollment_token"] == "enroll-token"

    @patch("backend.api.organizations.list_organizations")
    def test_list_organizations(self, mock_list, client, make_org_record) -> None:
        mock_list.return_value = [make_org_record(), make_org_record(org_id=2, name="Beta")]
        response = client.get("/api/v1/organizations")
        assert response.status_code == 200
        assert len(response.json()) == 2

    @patch("backend.api.organizations.get_organization_by_id")
    def test_get_organization_found(self, mock_get, client, make_org_record) -> None:
        mock_get.return_value = make_org_record(org_id=7)
        response = client.get("/api/v1/organizations/7")
        assert response.status_code == 200
        assert response.json()["id"] == 7

    @patch("backend.api.organizations.get_organization_by_id")
    def test_get_organization_not_found(self, mock_get, client) -> None:
        mock_get.side_effect = OrganizationIdNotFoundError("missing")
        response = client.get("/api/v1/organizations/999")
        assert response.status_code == 404
        assert response.json()["detail"] == "Organization not found"

    def test_create_organization_validation_error(self, client) -> None:
        response = client.post("/api/v1/organizations", json={"name": ""})
        assert response.status_code == 422
