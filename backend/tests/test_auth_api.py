from unittest.mock import MagicMock, patch

from backend.api import auth as auth_api
from backend.auth_utils import hash_password, verify_password


class TestAuthUtils:
    def test_hash_and_verify_password(self) -> None:
        hashed = hash_password("secret123")
        assert verify_password("secret123", hashed) is True
        assert verify_password("wrong", hashed) is False


class TestRequireCredentials:
    def test_missing_fields(self) -> None:
        assert auth_api._require_credentials({}) is None
        assert auth_api._require_credentials({"username": "a"}) is None

    def test_invalid_types(self) -> None:
        assert auth_api._require_credentials({"username": 1, "password": "x"}) is None

    def test_valid_credentials(self) -> None:
        assert auth_api._require_credentials({"username": "a", "password": "b"}) == ("a", "b")


class TestSignupEndpoint:
    @patch("backend.api.auth.SessionLocal")
    @patch("backend.api.auth.hash_password", return_value="hashed")
    def test_signup_success(self, mock_hash, mock_session_local, client) -> None:
        session = MagicMock()
        mock_session_local.return_value = session
        session.query.return_value.filter.return_value.first.return_value = None

        created_user = MagicMock()
        created_user.agent_id = "agent-new"
        session.refresh.side_effect = lambda u: setattr(u, "agent_id", "agent-new")

        response = client.post(
            "/api/v1/signup",
            json={
                "username": "alice",
                "password": "secret",
                "name": "Alice",
                "email": "a@example.com",
                "department": "IT",
                "photo_url": "http://x",
            },
        )
        assert response.status_code == 200
        assert response.json() == {"status": "created", "agent_id": "agent-new"}
        mock_hash.assert_called_once_with("secret")
        session.add.assert_called_once()
        session.commit.assert_called_once()

    @patch("backend.api.auth.SessionLocal")
    def test_signup_missing_fields(self, mock_session_local, client) -> None:
        response = client.post("/api/v1/signup", json={"username": "alice"})
        assert response.json() == {"error": "missing fields"}

    @patch("backend.api.auth.SessionLocal")
    def test_signup_user_exists(self, mock_session_local, client) -> None:
        session = MagicMock()
        mock_session_local.return_value = session
        session.query.return_value.filter.return_value.first.return_value = MagicMock()

        response = client.post(
            "/api/v1/signup",
            json={"username": "alice", "password": "secret"},
        )
        assert response.json() == {"error": "user exists"}


class TestLoginEndpoint:
    @patch("backend.api.auth.SessionLocal")
    @patch("backend.api.auth.verify_password", return_value=True)
    def test_login_success(self, mock_verify, mock_session_local, client, make_user) -> None:
        session = MagicMock()
        mock_session_local.return_value = session
        user = make_user()
        session.query.return_value.filter.return_value.first.return_value = user

        response = client.post(
            "/api/v1/login",
            json={"username": "alice", "password": "secret"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["agent_id"] == "agent-user1"
        assert body["username"] == "alice"

    @patch("backend.api.auth.SessionLocal")
    def test_login_missing_fields(self, mock_session_local, client) -> None:
        response = client.post("/api/v1/login", json={})
        assert response.json() == {"error": "missing fields"}

    @patch("backend.api.auth.SessionLocal")
    def test_login_user_not_found(self, mock_session_local, client) -> None:
        session = MagicMock()
        mock_session_local.return_value = session
        session.query.return_value.filter.return_value.first.return_value = None

        response = client.post(
            "/api/v1/login",
            json={"username": "ghost", "password": "secret"},
        )
        assert response.json() == {"error": "user not found"}

    @patch("backend.api.auth.SessionLocal")
    def test_login_invalid_hash_type(self, mock_session_local, client, make_user) -> None:
        session = MagicMock()
        mock_session_local.return_value = session
        user = make_user(password_hash=123)  # type: ignore[arg-type]
        session.query.return_value.filter.return_value.first.return_value = user

        response = client.post(
            "/api/v1/login",
            json={"username": "alice", "password": "secret"},
        )
        assert response.json() == {"error": "invalid password"}

    @patch("backend.api.auth.SessionLocal")
    @patch("backend.api.auth.verify_password", return_value=False)
    def test_login_wrong_password(self, mock_verify, mock_session_local, client, make_user) -> None:
        session = MagicMock()
        mock_session_local.return_value = session
        user = make_user(password_hash="hashed")
        session.query.return_value.filter.return_value.first.return_value = user

        response = client.post(
            "/api/v1/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert response.json() == {"error": "invalid password"}
