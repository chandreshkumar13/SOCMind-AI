"""Accounts mode: creating users, signing in with the lockout rule, and sessions (see docs/SECURITY.md).

Rules, in one place:
- Login: a username and password. An unknown username and a wrong password get the same answer, after the same amount of work.
- Lockout: after LOGIN_MAX_FAILURES failed attempts for one (username, client address) pair, that pair is refused for
  LOGIN_LOCK_MINUTES, even with the right password. The lock applies to every name the same way, so it reveals nothing about
  which names exist. Failures older than the lock window do not count towards the next lock.
- Sessions: an opaque random token in an HttpOnly cookie. Only its SHA-256 is stored. A session ends after SESSION_IDLE_MINUTES
  without use, or SESSION_ABSOLUTE_HOURS after login, whichever comes first, when it is logged out, or when its user is disabled.
- Disabled users: cannot sign in, and their open sessions stop working on their next request.

Times are naive UTC, as in the rest of the application (app/core/clock.py). Every function takes `now` so tests can use a clock.
"""
import hashlib
import re
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.core.config import settings
from app.models.auth_models import AuthSession, LoginAttempt, UserAccount
from app.services.passwords import (
    MAX_PASSWORD_LENGTH, hash_password, password_policy_error, verify_password, verify_unknown_user,
)

ROLES = ("viewer", "analyst", "approver")
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
SESSION_COOKIE = "socmind_session"
CSRF_HEADER = "X-CSRF-Token"
_TOUCH_INTERVAL = timedelta(seconds=60)     # last_seen_at is written at most once a minute, to keep writes down


def normalise_username(raw) -> Optional[str]:
    """The stored form of a username: trimmed, lower-case, 3 to 64 characters of letters, digits, dot, dash and underscore.
    None when the text cannot be a username. Nothing else is accepted, so a name can never be used to inject anything."""
    if not isinstance(raw, str):
        return None
    name = raw.strip().lower()
    return name if USERNAME_PATTERN.fullmatch(name) else None


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def csrf_for_token(token: str) -> str:
    """The CSRF token of the session that holds `token`. It is derived, not stored: the server recomputes it from the cookie on
    each request, so the database holds only the session's hash. Only someone who has the cookie can compute it."""
    return hashlib.sha256(("csrf:" + token).encode("utf-8")).hexdigest()


def create_user(db: Session, username: str, role: str, password: str) -> UserAccount:
    """Creates an account. Raises ValueError with a plain message for any problem. The password is hashed, never stored as given."""
    name = normalise_username(username)
    if name is None:
        raise ValueError("A username is 3 to 64 characters: letters, digits, '.', '-' or '_', starting with a letter or digit.")
    if role not in ROLES:
        raise ValueError(f"The role must be one of: {', '.join(ROLES)}.")
    problem = password_policy_error(password)
    if problem:
        raise ValueError(problem)
    if db.query(UserAccount).filter(UserAccount.username == name).first() is not None:
        raise ValueError("That username already exists.")
    user = UserAccount(username=name, password_hash=hash_password(password), role=role, is_active=True, created_at=utc_now())
    db.add(user)
    db.commit()
    return user


def set_active(db: Session, username: str, active: bool, now: Optional[datetime] = None) -> UserAccount:
    """Enables or disables an account. Disabling also ends every open session of that account."""
    name = normalise_username(username)
    user = db.query(UserAccount).filter(UserAccount.username == name).first() if name else None
    if user is None:
        raise ValueError("No account has that username.")
    user.is_active = bool(active)
    if not active:
        now = now or utc_now()
        for row in db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)):
            row.revoked_at = now
            row.revoke_reason = "disabled"
    db.commit()
    return user


def _attempt_row(db: Session, name: str, client_ip: str) -> Optional[LoginAttempt]:
    return db.query(LoginAttempt).filter(LoginAttempt.username == name, LoginAttempt.client_ip == client_ip).first()


def locked_until(db: Session, name: str, client_ip: str, now: datetime) -> Optional[datetime]:
    row = _attempt_row(db, name, client_ip)
    if row is not None and row.locked_until is not None and row.locked_until > now:
        return row.locked_until
    return None


def _record_failure(db: Session, name: str, client_ip: str, now: datetime) -> None:
    window = timedelta(minutes=settings.LOGIN_LOCK_MINUTES)
    row = _attempt_row(db, name, client_ip)
    if row is None:
        row = LoginAttempt(username=name, client_ip=client_ip, failures=0)
        db.add(row)
    if row.last_failure_at is None or now - row.last_failure_at > window:
        row.failures = 0                       # an old run of failures does not count towards a new lock
    row.failures += 1
    row.last_failure_at = now
    if row.failures >= settings.LOGIN_MAX_FAILURES:
        row.locked_until = now + window
        row.failures = 0
    # forget old counters for names that were only ever tried once or twice
    db.query(LoginAttempt).filter(LoginAttempt.last_failure_at < now - timedelta(days=1),
                                  (LoginAttempt.locked_until.is_(None)) | (LoginAttempt.locked_until < now)).delete(synchronize_session=False)
    db.commit()


def _clear_failures(db: Session, name: str, client_ip: str) -> None:
    db.query(LoginAttempt).filter(LoginAttempt.username == name, LoginAttempt.client_ip == client_ip).delete(synchronize_session=False)
    db.commit()


def authenticate(db: Session, raw_username, password: str, client_ip: str, now: Optional[datetime] = None) -> Tuple[str, Optional[UserAccount]]:
    """Checks a sign-in attempt. Returns (outcome, user) where outcome is "ok", "locked" or "bad_credentials".

    "bad_credentials" covers an unknown name, a wrong password and a disabled account alike, so the answer reveals none of them."""
    now = now or utc_now()
    if not isinstance(password, str) or not password or len(password) > MAX_PASSWORD_LENGTH:
        # refused before any hashing, so an oversized value cannot make the server work hard; the same dummy work is done
        verify_unknown_user("")
        return "bad_credentials", None
    name = normalise_username(raw_username)
    if name is None:
        verify_unknown_user(password)
        return "bad_credentials", None
    if locked_until(db, name, client_ip, now) is not None:
        return "locked", None
    user = db.query(UserAccount).filter(UserAccount.username == name).first()
    if user is None:
        verify_unknown_user(password)
        _record_failure(db, name, client_ip, now)
        return "bad_credentials", None
    matches = verify_password(password, user.password_hash)
    if not user.is_active or not matches:
        _record_failure(db, name, client_ip, now)
        return "bad_credentials", None
    _clear_failures(db, name, client_ip)
    return "ok", user


def create_session(db: Session, user: UserAccount, now: Optional[datetime] = None) -> Tuple[str, AuthSession]:
    """Starts a session. Returns (the raw token for the cookie, the stored row). The raw token is not kept anywhere else."""
    now = now or utc_now()
    token = secrets.token_urlsafe(32)
    row = AuthSession(
        id=_token_id(token),
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        absolute_expires_at=now + timedelta(hours=settings.SESSION_ABSOLUTE_HOURS),
    )
    db.add(row)
    db.query(AuthSession).filter(AuthSession.absolute_expires_at < now - timedelta(days=1)).delete(synchronize_session=False)
    db.commit()
    return token, row


def session_for_token(db: Session, token: str, now: Optional[datetime] = None) -> Optional[Tuple[AuthSession, UserAccount]]:
    """The live session and its user for a cookie value, or None. Ends a session that has expired or whose user is disabled."""
    if not token:
        return None
    now = now or utc_now()
    row = db.get(AuthSession, _token_id(token))
    if row is None or row.revoked_at is not None:
        return None
    user = db.get(UserAccount, row.user_id)
    if user is None:
        return None
    idle_limit = timedelta(minutes=settings.SESSION_IDLE_MINUTES)
    if now >= row.absolute_expires_at:
        _end(db, row, "expired", now)
        return None
    if now - row.last_seen_at > idle_limit:
        _end(db, row, "expired", now)
        return None
    if not user.is_active:
        _end(db, row, "disabled", now)
        return None
    if now - row.last_seen_at >= _TOUCH_INTERVAL:
        row.last_seen_at = now
        db.commit()
    return row, user


def _end(db: Session, row: AuthSession, reason: str, now: datetime) -> None:
    row.revoked_at = now
    row.revoke_reason = reason
    db.commit()


def end_session(db: Session, row: AuthSession, reason: str = "logout", now: Optional[datetime] = None) -> None:
    if row.revoked_at is None:
        _end(db, row, reason, now or utc_now())


def user_count(db: Session, active_only: bool = True) -> int:
    query = db.query(UserAccount)
    if active_only:
        query = query.filter(UserAccount.is_active.is_(True))
    return query.count()
