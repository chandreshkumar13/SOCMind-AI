"""Authentication and roles (see docs/SECURITY.md).

AUTH_MODE=disabled (default) is the demo mode: no token is required, every action is allowed and the reviewer name is
whatever the request says. It is labelled as such in /auth/me and /config. Do not expose it to untrusted networks.

AUTH_MODE=token: every request must send 'Authorization: Bearer <token>', where the token is one of AUTH_TOKENS. Each entry
names a person and a role. Roles are ordered: viewer (read) < analyst (work alerts and the pipeline, simulate) < approver
(approve or reject a proposed response). Missing or unknown tokens get 401; a known token without the role gets 403.
"""
import hmac
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings

ROLE_RANK = {"viewer": 0, "analyst": 1, "approver": 2}
MIN_TOKEN_LENGTH = 16


@dataclass(frozen=True)
class Principal:
    name: Optional[str]          # None in disabled mode: nobody is authenticated
    role: str
    mode: str                    # "disabled" or "token"

    @property
    def authenticated(self) -> bool:
        return self.mode == "token"


# Environments where the open demo mode is allowed. Anything else (production, staging, an unset or misspelt value that is not
# one of these) must use token mode, so the API cannot be left open by accident.
OPEN_MODE_ENVIRONMENTS = frozenset({"development", "test"})


def validate_auth_config(mode: str, tokens: List[Dict[str, Any]], environment: str = "development") -> None:
    """Refuses a configuration that would silently leave the API open or unusable. Raises ValueError with the reason.

    Error messages never include a token value."""
    if mode not in ("disabled", "token"):
        raise ValueError(f"AUTH_MODE must be 'disabled' or 'token', not {mode!r}")
    if mode == "disabled":
        env = str(environment or "").strip().lower()
        if env not in OPEN_MODE_ENVIRONMENTS:
            raise ValueError(
                f"AUTH_MODE=disabled is refused because ENVIRONMENT is {str(environment)!r}. Demo mode without a token is only "
                "allowed for ENVIRONMENT=development or test. For any other environment set AUTH_MODE=token and AUTH_TOKENS.")
        return
    if not tokens:
        raise ValueError("AUTH_MODE is 'token' but AUTH_TOKENS has no tokens configured")
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


def current_principal(request: Request) -> Principal:
    if settings.AUTH_MODE != "token":
        return Principal(name=None, role="approver", mode="disabled")
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    presented = presented.strip()
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "A bearer token is required (Authorization: Bearer <token>).",
                            headers={"WWW-Authenticate": "Bearer"})
    match = None
    for entry in settings.AUTH_TOKENS:
        # compare every entry so the time taken does not reveal which entry matched
        if hmac.compare_digest(presented.encode("utf-8"), str(entry.get("token", "")).encode("utf-8")):
            match = entry
    if match is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The token is not recognised.", headers={"WWW-Authenticate": "Bearer"})
    return Principal(name=str(match["name"]), role=str(match["role"]), mode="token")


def require(role: str):
    """A FastAPI dependency that admits principals with at least `role`. Use it as Depends(require('analyst'))."""
    if role not in ROLE_RANK:
        raise ValueError(f"unknown role {role!r}")

    def check(principal: Principal = Depends(current_principal)) -> Principal:
        if ROLE_RANK[principal.role] < ROLE_RANK[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"This action needs the '{role}' role.")
        return principal

    return check
