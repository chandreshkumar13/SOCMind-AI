"""Sign-in, sign-out and "who am I" (see docs/SECURITY.md).

Public: GET /auth/status (tells the browser whether to show a sign-in page, the first-run setup form or a guest button) and, in
accounts mode only, POST /auth/login, POST /auth/setup (the first approver, while no account exists) and POST /auth/guest (a
read-only guest session, only when ALLOW_GUEST is on).
Any valid caller: GET /auth/me. Logout: POST /auth/logout, which needs a valid session (and its CSRF token when the session is a
cookie). Failed sign-ins, lockouts, sign-ins and sign-outs are written to the audit log, without any password or token.

Accounts mode only (404 in the other modes): an approver lists, creates, disables and enables accounts (GET and POST /auth/users,
POST /auth/users/{username}/disable and /enable, POST /auth/users/{username}/password to reset a password), and any signed-in
account changes its own password (POST /auth/password). There is no public sign-up. A password or a password hash is never returned, logged or written to the audit log.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import Principal, current_principal, require, session_cookie_secure
from app.core.clock import utc_now
from app.core.config import settings
from app.db.session import get_db
from app.models.auth_models import AuthSession, UserAccount
from app.schemas.common import utc_iso
from app.services import accounts, guest
from app.services.audit import log_action

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=2048)     # the real limits are applied by the account service


class CreateUserBody(BaseModel):
    username: str = Field(max_length=256)
    role: str = Field(max_length=32)
    password: str = Field(max_length=2048)     # the real limits are applied by the account service


class ChangePasswordBody(BaseModel):
    current_password: str = Field(max_length=2048)
    new_password: str = Field(max_length=2048)


class SetupBody(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=2048)     # the real limits are applied by the account service
    confirm: str = Field(max_length=2048)


class ResetPasswordBody(BaseModel):
    new_password: str = Field(max_length=2048)


class GuestBody(BaseModel):
    """No fields. It exists so the request must be JSON, which a cross-site HTML form cannot send."""


def _seconds_left(expires_at) -> Optional[int]:
    """Whole seconds until a session's absolute expiry, from the server's clock, so the page does not depend on its own clock."""
    if expires_at is None:
        return None
    return max(0, int((expires_at - utc_now()).total_seconds()))


def _user_record(user: UserAccount) -> Dict[str, Any]:
    """The only shape in which an account leaves the API. No password and no hash."""
    return {"username": user.username, "role": user.role, "is_active": bool(user.is_active), "created_at": utc_iso(user.created_at)}


def _client_address(request: Request) -> str:
    client = request.client
    return (client.host if client and client.host else "unknown")[:64]


def _audit_name(raw: str) -> str:
    """The name written to the audit log for a sign-in attempt: the normalised name when it is valid, else a fixed label, so
    arbitrary text cannot be written as an actor."""
    return accounts.normalise_username(raw) or "(invalid username)"


@router.get("/auth/status", summary="How this server signs people in (public)")
def auth_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """What the page needs before it can show anything: whether to ask for sign-in, whether the first administrator still has to be
    created (accounts mode with no account at all), and whether a guest button is offered (accounts mode with ALLOW_GUEST)."""
    mode = settings.AUTH_MODE
    accounts_mode = mode == "accounts"
    return {"mode": mode, "login_required": mode in ("token", "accounts"), "sign_in": accounts_mode,
            "setup_required": accounts_mode and accounts.setup_required(db),
            "guest_allowed": accounts_mode and bool(settings.ALLOW_GUEST)}


def _accounts_mode_only() -> None:
    """Runs before the request body is checked, so in any other mode the endpoint answers 404 whatever is sent."""
    if settings.AUTH_MODE != "accounts":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _guest_allowed_only() -> None:
    if settings.AUTH_MODE != "accounts" or not settings.ALLOW_GUEST:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _setup_still_open(db: Session = Depends(get_db)) -> None:
    """Runs before the request body is checked: once any account exists, setup answers 409 whatever is sent."""
    if not accounts.setup_required(db):
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already complete.")


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(key=accounts.SESSION_COOKIE, value=token, max_age=settings.SESSION_ABSOLUTE_HOURS * 3600,
                        httponly=True, secure=session_cookie_secure(), samesite="strict", path="/")


def _session_payload(name: str, role: str, token: str, absolute_expires_at, is_guest: bool = False) -> Dict[str, Any]:
    """What a new cookie session returns to the page: who it is, its CSRF token and its timing."""
    out: Dict[str, Any] = {
        "authenticated": True, "mode": "accounts", "name": name, "role": role,
        "csrf_token": accounts.csrf_for_token(token),
        "idle_timeout_minutes": settings.SESSION_IDLE_MINUTES,
        "expires_at": absolute_expires_at.isoformat(),
        "expires_in_seconds": _seconds_left(absolute_expires_at),
    }
    if is_guest:
        out["guest"] = True
    return out


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
    _set_session_cookie(response, token)
    log_action(db, actor=user.username, action="LOGIN", target_id=None, details={"client": address})
    db.commit()
    return _session_payload(user.username, user.role, token, row.absolute_expires_at)


@router.post("/auth/setup", summary="Create the first administrator and sign in (accounts mode, only while no account exists)",
             dependencies=[Depends(_accounts_mode_only), Depends(_setup_still_open)])
def setup(body: SetupBody, request: Request, response: Response, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """First-run setup. It creates ONE approver and signs that person in, exactly as /auth/login does. It works only while the
    account table is empty; afterwards it answers 409 whatever is sent, so it cannot be used to add accounts or take one over."""
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Send the setup as JSON.")
    if body.password != body.confirm:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "The two passwords do not match.")
    try:
        user = accounts.create_first_approver(db, body.username, body.password)
    except accounts.SetupClosed as problem:
        raise HTTPException(status.HTTP_409_CONFLICT, str(problem))
    except ValueError as problem:                # a bad username or password; the message never repeats the password
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(problem))
    address = _client_address(request)
    token, row = accounts.create_session(db, user)
    _set_session_cookie(response, token)
    log_action(db, actor=user.username, action="ACCOUNT_CREATED", target_id=user.username, details={"via": "first_run_setup"})
    log_action(db, actor=user.username, action="LOGIN", target_id=None, details={"client": address})
    db.commit()
    return _session_payload(user.username, user.role, token, row.absolute_expires_at)


@router.post("/auth/guest", summary="Open a read-only guest session (accounts mode, only when ALLOW_GUEST is on)",
             dependencies=[Depends(_guest_allowed_only)])
def guest_login(body: GuestBody, request: Request, response: Response, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """A viewer named "guest" with no account behind it (see app/services/guest.py). It can read and nothing else: every route that
    needs the analyst or approver role answers 403 to it."""
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Send the request as JSON.")
    token, row = guest.create_session()
    _set_session_cookie(response, token)
    log_action(db, actor=guest.GUEST_NAME, action="LOGIN", target_id=None, details={"client": _client_address(request), "guest": True})
    db.commit()
    return _session_payload(guest.GUEST_NAME, "viewer", token, row.absolute_expires_at, is_guest=True)


@router.post("/auth/logout", summary="End the current session")
def logout(response: Response, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Dict[str, Any]:
    if principal.session and principal.session_id:
        if principal.guest:
            guest.end_session(principal.session_id)
        else:
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
    if principal.guest:
        out["guest"] = True
    if principal.session:
        out["csrf_token"] = principal.csrf_token
        out["idle_timeout_minutes"] = settings.SESSION_IDLE_MINUTES
        out["expires_at"] = principal.expires_at.isoformat() if principal.expires_at else None
        out["expires_in_seconds"] = _seconds_left(principal.expires_at)
    return out


# ----------------------------------------------------------------------------------- account management (accounts mode only)
# The role check comes first, so a caller without a token still gets 401 and a role that is too low gets 403 in every mode; the
# accounts-mode check follows, so these routes answer 404 where accounts do not exist.
_APPROVER_IN_ACCOUNTS_MODE = [Depends(require("approver")), Depends(_accounts_mode_only)]


@router.get("/auth/users", summary="List accounts (approver, accounts mode)", dependencies=_APPROVER_IN_ACCOUNTS_MODE)
def list_users(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    return [_user_record(user) for user in accounts.list_users(db)]


@router.post("/auth/users", status_code=status.HTTP_201_CREATED, summary="Create an account (approver, accounts mode)",
             dependencies=_APPROVER_IN_ACCOUNTS_MODE)
def create_user(body: CreateUserBody, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Dict[str, Any]:
    try:
        user = accounts.create_user(db, body.username, body.role, body.password)
    except accounts.AccountExists as problem:
        raise HTTPException(status.HTTP_409_CONFLICT, str(problem))
    except ValueError as problem:                # a bad username, role or password; the message never repeats the password
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(problem))
    except IntegrityError:                       # two requests created the same name at the same moment
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "That username already exists.")
    log_action(db, actor=principal.name or "(unknown)", action="ACCOUNT_CREATED", target_id=user.username, details={"role": user.role})
    db.commit()
    return _user_record(user)


def _change_active(username: str, active: bool, principal: Principal, db: Session) -> Dict[str, Any]:
    acting = principal.name if principal.session else None      # only a signed-in account can be "yourself"
    try:
        user, sessions_ended, changed = accounts.change_active(db, acting, username, active)
    except accounts.AccountRuleError as problem:
        raise HTTPException(status.HTTP_409_CONFLICT, str(problem))
    except ValueError as problem:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(problem))
    if changed:
        log_action(db, actor=principal.name or "(unknown)", action="ACCOUNT_ENABLED" if active else "ACCOUNT_DISABLED",
                   target_id=user.username, details=None if active else {"sessions_ended": sessions_ended})
        db.commit()
    return _user_record(user)


@router.post("/auth/users/{username}/disable", summary="Disable an account and end its sessions (approver, accounts mode)",
             dependencies=_APPROVER_IN_ACCOUNTS_MODE)
def disable_user(username: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Dict[str, Any]:
    return _change_active(username, False, principal, db)


@router.post("/auth/users/{username}/enable", summary="Enable a disabled account (approver, accounts mode)",
             dependencies=_APPROVER_IN_ACCOUNTS_MODE)
def enable_user(username: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Dict[str, Any]:
    return _change_active(username, True, principal, db)


@router.post("/auth/users/{username}/password", summary="Reset another account's password and end its sessions (approver, accounts mode)",
             dependencies=_APPROVER_IN_ACCOUNTS_MODE)
def reset_user_password(username: str, body: ResetPasswordBody, principal: Principal = Depends(current_principal),
                        db: Session = Depends(get_db)) -> Dict[str, Any]:
    """An approver sets a new password for someone else (a forgotten password). Every session of that account ends. An approver
    changes their own password with /auth/password instead (409 here). Neither password is ever returned or recorded."""
    acting = principal.name if principal.session else None      # a static token has no account, so "your own account" cannot apply
    try:
        user, ended = accounts.reset_password(db, acting, username, body.new_password)
    except accounts.AccountRuleError as problem:
        raise HTTPException(status.HTTP_409_CONFLICT, str(problem))
    except accounts.AccountNotFound as problem:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(problem))
    except ValueError as problem:                # the new password is refused; the message never repeats a password
        db.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(problem))
    log_action(db, actor=principal.name or "(unknown)", action="PASSWORD_RESET", target_id=user.username, details={"sessions_ended": ended})
    db.commit()
    return {"status": "ok", "sessions_ended": ended}


@router.post("/auth/password", summary="Change your own password (accounts mode)",
             dependencies=[Depends(require("viewer")), Depends(_accounts_mode_only)])
def change_password(body: ChangePasswordBody, request: Request, principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)) -> Dict[str, Any]:
    if not principal.session or principal.guest:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a signed-in account can change a password.")
    user = db.query(UserAccount).filter(UserAccount.username == principal.name).first()
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    address = _client_address(request)
    outcome = accounts.verify_current_password(db, user, body.current_password, address)
    if outcome == "locked":
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"Too many failed attempts from this address. Try again in {settings.LOGIN_LOCK_MINUTES} minutes.")
    if outcome != "ok":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The current password is incorrect.")
    try:
        ended = accounts.change_password(db, user, body.current_password, body.new_password, principal.session_id)
    except ValueError as problem:                # the new password is refused; the message never repeats a password
        db.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(problem))
    log_action(db, actor=user.username, action="PASSWORD_CHANGED", target_id=user.username,
               details={"other_sessions_ended": ended, "client": address})
    db.commit()
    return {"status": "ok", "other_sessions_ended": ended}
