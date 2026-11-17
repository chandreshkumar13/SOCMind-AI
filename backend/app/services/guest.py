"""The read-only guest session (ALLOW_GUEST, accounts mode only; see docs/SECURITY.md).

A guest is a viewer named "guest". There is no account behind it: nothing is written to the user_accounts table, so a guest never
appears in the account list, cannot be disabled and cannot count as an approver. The session lives in this process's memory:

- Why not a database row? auth_sessions.user_id must name a real account (and SQLite cannot relax that on an existing database),
  and a placeholder account would show up in the Users table and in the "last active approver" rules.
- Why not a signed cookie? It needs a signing secret that this application does not have, and it could not be revoked at logout.
- The price of memory: guest sessions end when the server restarts, and they are not shared between worker processes. A guest simply
  opens a new session. The application runs one process (docs/SECURITY.md), and a stale cookie only means "sign in again".

The session follows the same rules as an account session: an opaque random token in the same HttpOnly cookie, only its SHA-256 kept,
the same CSRF token, the idle timeout and the absolute lifetime. The number of open guest sessions is capped, so an anonymous caller
cannot make the server hold an unbounded amount of memory: when the cap is reached, expired sessions are dropped first and then the
oldest open one.

Times are naive UTC, as in the rest of the application, and every function takes `now` so tests can use a clock.
"""
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from app.core.clock import utc_now
from app.core.config import settings
from app.services.accounts import token_id

GUEST_NAME = "guest"
MAX_GUEST_SESSIONS = 500


@dataclass
class GuestSession:
    id: str                       # SHA-256 hex of the session token; the token itself is not kept
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime


_LOCK = threading.Lock()
_SESSIONS: Dict[str, GuestSession] = {}


def _expired(row: GuestSession, now: datetime) -> bool:
    return now >= row.absolute_expires_at or now - row.last_seen_at > timedelta(minutes=settings.SESSION_IDLE_MINUTES)


def create_session(now: Optional[datetime] = None) -> Tuple[str, GuestSession]:
    """Starts a guest session. Returns (the raw token for the cookie, the stored row)."""
    now = now or utc_now()
    token = secrets.token_urlsafe(32)
    row = GuestSession(id=token_id(token), created_at=now, last_seen_at=now,
                       absolute_expires_at=now + timedelta(hours=settings.SESSION_ABSOLUTE_HOURS))
    with _LOCK:
        for key in [key for key, other in _SESSIONS.items() if _expired(other, now)]:
            del _SESSIONS[key]
        while len(_SESSIONS) >= MAX_GUEST_SESSIONS:
            del _SESSIONS[min(_SESSIONS, key=lambda key: _SESSIONS[key].created_at)]
        _SESSIONS[row.id] = row
    return token, row


def session_for_token(token: str, now: Optional[datetime] = None) -> Optional[GuestSession]:
    """The live guest session for a cookie value, or None. A session that has run out is dropped."""
    if not token:
        return None
    now = now or utc_now()
    key = token_id(token)
    with _LOCK:
        row = _SESSIONS.get(key)
        if row is None:
            return None
        if _expired(row, now):
            del _SESSIONS[key]
            return None
        row.last_seen_at = now
        return row


def end_session(session_id: Optional[str]) -> bool:
    """Ends a guest session by its id. True when one was open."""
    with _LOCK:
        return _SESSIONS.pop(session_id, None) is not None if session_id else False


def open_sessions() -> int:
    with _LOCK:
        return len(_SESSIONS)


def clear() -> None:
    """Drops every guest session (used by the tests, and could be used to log every guest out)."""
    with _LOCK:
        _SESSIONS.clear()
