"""Sign-in, sign-out and "who am I" (see docs/SECURITY.md).

Public: GET /auth/status (tells the browser whether to show a sign-in page) and POST /auth/login (only in accounts mode).
Any valid caller: GET /auth/me. Logout: POST /auth/logout, which needs a valid session (and its CSRF token when the session is a
cookie). Failed sign-ins, lockouts, sign-ins and sign-outs are written to the audit log, without any password or token.
"""
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import Principal, current_principal, session_cookie_secure
from app.core.config import settings
from app.db.session import get_db
from app.models.auth_models import AuthSession
from app.services import accounts
from app.services.audit import log_action

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=2048)     # the real limits are applied by the account service


def _client_address(request: Request) -> str:
    client = request.client
    return (client.host if client and client.host else "unknown")[:64]


def _audit_name(raw: str) -> str:
    """The name written to the audit log for a sign-in attempt: the normalised name when it is valid, else a fixed label, so
    arbitrary text cannot be written as an actor."""
    return accounts.normalise_username(raw) or "(invalid username)"


@router.get("/auth/status", summary="How this server signs people in (public)")
def auth_status() -> Dict[str, Any]:
    mode = settings.AUTH_MODE
    return {"mode": mode, "login_required": mode in ("token", "accounts"), "sign_in": mode == "accounts"}


def _accounts_mode_only() -> None:
    """Runs before the request body is checked, so in any other mode the endpoint answers 404 whatever is sent."""
    if settings.AUTH_MODE != "accounts":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


@router.post("/auth/login", summary="Sign in with a username and password (accounts mode)", dependencies=[Depends(_accounts_mode_only)])
def login(body: LoginBody, request: Request, response: Response, db: Session = Depends(get_db)) -> Dict[str, Any]:
    if settings.AUTH_MODE != "accounts":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Send the sign-in as JSON.")
    address = _client_address(request)
    outcome, user = accounts.authenticate(db, body.username, body.password, address)
    if outcome == "locked":
        log_action(db, actor=_audit_name(body.username), action="LOGIN_LOCKED", target_id=None, details={"client": address})
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"Too many failed sign-in attempts from this address. Try again in {settings.LOGIN_LOCK_MINUTES} minutes.")
    if outcome != "ok" or user is None:
        log_action(db, actor=_audit_name(body.username), action="LOGIN_FAILED", target_id=None, details={"client": address})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password.")
    token, row = accounts.create_session(db, user)
    response.set_cookie(key=accounts.SESSION_COOKIE, value=token, max_age=settings.SESSION_ABSOLUTE_HOURS * 3600,
                        httponly=True, secure=session_cookie_secure(), samesite="strict", path="/")
    log_action(db, actor=user.username, action="LOGIN", target_id=None, details={"client": address})
    db.commit()
    return {
        "authenticated": True, "mode": "accounts", "name": user.username, "role": user.role,
        "csrf_token": accounts.csrf_for_token(token),
        "idle_timeout_minutes": settings.SESSION_IDLE_MINUTES,
        "expires_at": row.absolute_expires_at.isoformat(),
    }


@router.post("/auth/logout", summary="End the current session")
def logout(response: Response, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Dict[str, Any]:
    if principal.session and principal.session_id:
        row: Optional[AuthSession] = db.get(AuthSession, principal.session_id)
        if row is not None:
            accounts.end_session(db, row, reason="logout")
        log_action(db, actor=principal.name or "(unknown)", action="LOGOUT", target_id=None, details=None)
        db.commit()
    response.delete_cookie(key=accounts.SESSION_COOKIE, path="/", httponly=True, secure=session_cookie_secure(), samesite="strict")
    return {"authenticated": False}


@router.get("/auth/me", summary="Who am I (mode, name and role of the caller)")
def who_am_i(principal: Principal = Depends(current_principal)) -> Dict[str, Any]:
    """In disabled mode no one is authenticated and every action is allowed (demo). In token mode the name and role come
    from the token. In accounts mode the response also carries the session's CSRF token and its absolute expiry, so the page
    can send the CSRF header on writes."""
    out: Dict[str, Any] = {"mode": principal.mode, "authenticated": principal.authenticated, "name": principal.name, "role": principal.role}
    if principal.session:
        out["csrf_token"] = principal.csrf_token
        out["idle_timeout_minutes"] = settings.SESSION_IDLE_MINUTES
        out["expires_at"] = principal.expires_at.isoformat() if principal.expires_at else None
    return out
