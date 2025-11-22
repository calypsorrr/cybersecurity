from functools import wraps
from typing import Callable, Optional

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from cybercheck.config import ENGAGEMENT_TOKEN
from cybercheck.models.db import fetch_user, upsert_user


def verify_token(token: str) -> bool:
    if not ENGAGEMENT_TOKEN:
        return False
    return token.strip() == ENGAGEMENT_TOKEN


def current_user() -> Optional[dict]:
    user = session.get("user")
    return user if user else None


def authenticate_user(username: str, password: str) -> bool:
    row = fetch_user(username)
    if not row or not row["password_hash"]:
        return False
    if check_password_hash(row["password_hash"], password):
        session["user"] = {"username": row["username"], "role": row["role"]}
        return True
    return False


def bootstrap_admin(password: str) -> None:
    password_hash = generate_password_hash(password)
    upsert_user("admin", password_hash, "admin")


def require_active_session(request_token: str) -> bool:
    # Prefer an authenticated session but allow the legacy engagement token for backward compatibility
    if current_user():
        return True
    return verify_token(request_token)


def require_role(role: str) -> Callable:
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or user.get("role") not in {role, "admin"}:
                return {"error": "forbidden"}, 403
            return view(*args, **kwargs)

        return wrapper

    return decorator
