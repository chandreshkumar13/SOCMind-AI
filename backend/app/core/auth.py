"""Authentication and roles (see docs/SECURITY.md).

AUTH_MODE=disabled (default) is the demo mode: no token is required, every action is allowed and the reviewer name is
whatever the request says. It is labelled as such in /auth/me and /config. Do not expose it to untrusted networks.

AUTH_MODE=token: every request must send 'Authorization: Bearer <token>', where the token is one of AUTH_TOKENS. Each entry
names a person and a role. Roles are ordered: viewer (read) < analyst (work alerts and the pipeline, simulate) < approver
(approve or reject a proposed response). Missing or unknown tokens get 401; a known token without the role gets 403.

AUTH_MODE=accounts: people sign in with a username and password (POST /auth/login) and then carry an HttpOnly session cookie.
Static bearer tokens from AUTH_TOKENS are still accepted, for automation, exactly as in token mode. A cookie session is checked
on every request (idle timeout, absolute lifetime, revocation, disabled users). A state-changing request that uses a cookie
session must also send the session's CSRF token in the X-CSRF-Token header; a bearer token is not sent automatically by a
browser, so it does not need one.
"""
import hmac
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.services import accounts

ROLE_RANK = {"viewer": 0, "analyst": 1, "approver": 2}
MIN_TOKEN_LENGTH = 16
AUTH_MODES = ("disabled", "token", "accounts")
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class Principal:
    name: Optional[str]          # None in disabled mode: nobody is authenticated
    role: str
    mode: str                    # "disabled", "token" (a static bearer token) or "accounts" (a cookie session)
    session: bool = False        # True when the caller is a cookie session
    session_id: Optional[str] = None
    csrf_token: Optional[str] = None
    expires_at: Optional[datetime] = None   # absolute expiry of a cookie session (naive UTC)

    @property
    def authenticated(self) -> bool:
        return self.mode in ("token", "accounts")


# Environments where the open demo mode is allowed. Anything else (production, staging, an unset or misspelt value that is not
# one of these) must use token or accounts mode, so the API cannot be left open by accident.
OPEN_MODE_ENVIRONMENTS = frozenset({"development", "test"})


def session_cookie_secure() -> bool:
    """Whether the session cookie carries the Secure flag. Required outside development and test unless explicitly disabled
    there, which validate_auth_config refuses for production-like environments."""
    if settings.SESSION_COOKIE_SECURE is not None:
        return bool(settings.SESSION_COOKIE_SECURE)
    return str(settings.ENVIRONMENT or "").strip().lower() not in OPEN_MODE_ENVIRONMENTS


def _check_static_tokens(tokens: List[Any]) -> None:
    seen = set()
    for entry in tokens:
        if not isinstance(entry, dict):
            raise ValueError("each AUTH_TOKENS entry must be an object with name, role and token")
        if entry.get("role") not in ROLE_RANK:
            raise ValueError(f"each AUTH_TOKENS entry needs a role of viewer, analyst or approver (got {entry.get('role')!r})")
        if not entry.get("name"):
            raise ValueError("each AUTH_TOKENS entry needs a name")
        token = str(entry.get("token") or "")
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"each AUTH_TOKENS token must be at least {MIN_TOKEN_LENGTH} characters long")
        # A token travels in an HTTP header: printable ASCII without spaces, so it can always be sent back unchanged
        if not token.isascii() or not token.isprintable() or any(ch.isspace() for ch in token):
            raise ValueError("AUTH_TOKENS tokens may only contain printable ASCII characters, without spaces")
        if token in seen:
            # Two entries with one token would make the role depend on list order. Refused instead.
            raise ValueError("two AUTH_TOKENS entries share the same token; every token must be unique")
        seen.add(token)


def validate_auth_config(mode: str, tokens: List[Dict[str, Any]], environment: str = "development",
                         cookie_secure: Optional[bool] = None) -> None:
    """Refuses a configuration that would silently leave the API open or unusable. Raises ValueError with the reason.

    Error messages never include a token value or a password."""
    if mode not in AUTH_MODES:
        raise ValueError(f"AUTH_MODE must be 'disabled', 'token' or 'accounts', not {mode!r}")
    env = str(environment or "").strip().lower()
    if mode == "disabled":
        if env not in OPEN_MODE_ENVIRONMENTS:
            raise ValueError(
                f"AUTH_MODE=disabled is refused because ENVIRONMENT is {str(environment)!r}. Demo mode without a token is only "
                "allowed for ENVIRONMENT=development or test. For any other environment set AUTH_MODE=token or AUTH_MODE=accounts.")
        return
    if mode == "token":
        if not tokens:
            raise ValueError("AUTH_MODE is 'token' but AUTH_TOKENS has no tokens configured")
        _check_static_tokens(tokens)
        return
    # accounts: people sign in with a password. Static tokens are optional here (for automation), but if given they must be valid.
    if env not in OPEN_MODE_ENVIRONMENTS and cookie_secure is False:
        raise ValueError("SESSION_COOKIE_SECURE=false is refused outside development and test: session cookies must be Secure (HTTPS).")
    if tokens:
        _check_static_tokens(tokens)


def _presented_bearer(request: Request) -> str:
    scheme, _, presented = request.headers.get("authorization", "").partition(" ")
    return presented.strip() if scheme.lower() == "bearer" else ""


def _static_token_principal(presented: str) -> Optional[Principal]:
    match = None
    for entry in settings.AUTH_TOKENS:
        # compare every entry so the time taken does not reveal which entry matched
        if hmac.compare_digest(presented.encode("utf-8"), str(entry.get("token", "")).encode("utf-8")):
            match = entry
    if match is None:
        return None
    return Principal(name=str(match["name"]), role=str(match["role"]), mode="token")


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    """Who is calling.

    Token mode: the bearer token, as before.
    Accounts mode: a valid account session cookie is checked first and takes precedence. If the request also carries a bearer
    token, the cookie's account is still the identity, so the reviewer and the role are the account's. A write made with a
    cookie must carry the session's CSRF token. A static bearer token is used only when no valid cookie session exists, so
    automation keeps working alongside people who sign in.
    """
    mode = settings.AUTH_MODE
    if mode == "disabled":
        return Principal(name=None, role="approver", mode="disabled")
    presented = _presented_bearer(request)
    if mode == "accounts":
        cookie = request.cookies.get(accounts.SESSION_COOKIE, "")
        if cookie:
            found = accounts.session_for_token(db, cookie)
            if found is not None:
                row, user = found
                expected_csrf = accounts.csrf_for_token(cookie)
                if request.method in STATE_CHANGING_METHODS:
                    sent = request.headers.get(accounts.CSRF_HEADER, "")
                    if not hmac.compare_digest(sent.encode("utf-8"), expected_csrf.encode("utf-8")):
                        raise HTTPException(status.HTTP_403_FORBIDDEN, "A valid CSRF token is required for this request.")
                return Principal(name=user.username, role=user.role, mode="accounts", session=True, session_id=row.id,
                                 csrf_token=expected_csrf, expires_at=row.absolute_expires_at)
        # no valid session: a static bearer token, as in token mode
        if presented:
            principal = _static_token_principal(presented)
            if principal is not None:
                return principal
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The token is not recognised.", headers={"WWW-Authenticate": "Bearer"})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    # token mode: unchanged
    if presented:
        principal = _static_token_principal(presented)
        if principal is not None:
            return principal
    if not presented:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "A bearer token is required (Authorization: Bearer <token>).",
                            headers={"WWW-Authenticate": "Bearer"})
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The token is not recognised.", headers={"WWW-Authenticate": "Bearer"})


def require(role: str):
    """A FastAPI dependency that admits principals with at least `role`. Use it as Depends(require('analyst'))."""
    if role not in ROLE_RANK:
        raise ValueError(f"unknown role {role!r}")

    def check(principal: Principal = Depends(current_principal)) -> Principal:
        if ROLE_RANK[principal.role] < ROLE_RANK[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"This action needs the '{role}' role.")
        return principal

    return check
