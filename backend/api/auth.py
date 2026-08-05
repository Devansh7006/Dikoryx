from fastapi import APIRouter
from backend.database import SessionLocal, User
from backend.auth_utils import hash_password, verify_password
from datetime import datetime
from backend.database import LoginLog

router = APIRouter()

# ------------------ SIGNUP ------------------

def _require_credentials(payload: dict) -> tuple[str, str] | None:
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        return None
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    return username, password


@router.post("/api/v1/signup")
def signup(payload: dict):
    session = SessionLocal()

    credentials = _require_credentials(payload)
    if credentials is None:
        return {"error": "missing fields"}
    username, password = credentials

    name = payload.get("name")
    email = payload.get("email")
    department = payload.get("department")
    photo_url = payload.get("photo_url")

    existing = session.query(User).filter(User.username == username).first()
    if existing:
        return {"error": "user exists"}

    user = User(
        username=username,
        password_hash=hash_password(password),
        name=name,
        email=email,
        department=department,   # ✅ FIXED
        photo_url=photo_url
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return {
        "status": "created",
        "agent_id": user.agent_id
    }


# ------------------ LOGIN ------------------
# ------------------ LOGIN ------------------

@router.post("/api/v1/login")
def login(payload: dict):
    session = SessionLocal()

    credentials = _require_credentials(payload)
    if credentials is None:
        return {"error": "missing fields"}

    username, password = credentials

    user = session.query(User).filter(User.username == username).first()

    if not user:
        return {"error": "user not found"}

    stored_hash = user.password_hash

    if not isinstance(stored_hash, str):
        return {"error": "invalid password"}

    if not verify_password(password, stored_hash):
        return {"error": "invalid password"}

    # ------------------ SAVE LOGIN LOG ------------------

    login_log = LoginLog(
        user_id=user.id,
        username=user.username,
        login_time=datetime.utcnow(),
        ip_address="unknown",
        user_agent="web"
    )

    session.add(login_log)
    session.commit()

    # ------------------ RETURN USER ------------------

    return {
        "status": "ok",
        "agent_id": user.agent_id,
        "user_id": user.id,
        "username": user.username,
        "name": user.name,
        "email": user.email,
        "department": user.department,
        "photo_url": user.photo_url
    }