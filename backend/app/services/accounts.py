"""Accounts mode: creating users, signing in with the lockout rule, and sessions (see docs/SECURITY.md).

Rules, in one place:
- Login: a username and password. An unknown username and a wrong password get the same answer, after the same amount of work.
- Lockout: after LOGIN_MAX_FAILURES failed attempts for one (username, client address) pair, that pair is refused for
  LOGIN_LOCK_MINUTES, even with the right password. The lock applies to every name the same way, so it reveals nothing about
  which names exist. Failures older than the lock window do not count towards the next lock.
- Sessions: an opaque random token in an HttpOnly cookie. Only its SHA-256 is stored. A session ends after SESSION_IDLE_MINUTES
  without use, or SESSION_ABSOLUTE_HOURS after login, whichever comes first, when it is logged out, or when its user is disabled.
- Disabled users: cannot sign in, and their open sessions stop working on their next request.
- First-run setup: while no account exists at all, anyone can create the first approver (POST /auth/setup); it is refused for good
  once any account exists, even a disabled one. The check and the insert are one SQL statement, so two requests cannot both win.
- Account management (an approver, through the API): create an account, disable or enable one, change one's own password, and reset
  someone else's (which ends that person's sessions and clears their sign-in lockout).
  Disabling has two safety rules: nobody disables their own account, and the last active approver is never disabled. A password
  change needs the current password (a wrong one counts towards the same lockout as a wrong sign-in) and ends every other session.

Times are naive UTC, as in the rest of the application (app/core/clock.py). Every function takes `now` so tests can use a clock.
"""
import hashlib
import re
import secrets
import threading
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from sqlalchemy import Boolean, DateTime, exists, insert, literal, select
from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.core.config import settings
from app.models.auth_models import AuthSession, LoginAttempt, UserAccount
from app.services.passwords import (
    MAX_PASSWORD_LENGTH, hash_password, password_policy_error, verify_password, verify_unknown_user,
)

ROLES = ("viewer", "analyst", "approver")
RESERVED_USERNAMES = frozenset({"guest"})   # the name shown for the read-only guest session (services/guest.py); never an account
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
SESSION_COOKIE = "socmind_session"
CSRF_HEADER = "X-CSRF-Token"
_TOUCH_INTERVAL = timedelta(seconds=60)     # last_seen_at is written at most once a minute, to keep writes down

# One lock for the account rules below, so two requests in this process cannot both pass the "last approver" check before either
# disables an account. It does not span several worker processes (the application runs one; see docs/SECURITY.md).
_RULES_LOCK = threading.Lock()


class AccountExists(ValueError):
    """The username is already taken. A ValueError, so callers that only catch ValueError (the command line) behave as before."""


class AccountRuleError(ValueError):
    """A change that a safety rule refuses, for example disabling the last active approver."""


class AccountNotFound(ValueError):
    """No account has the username that was asked for (a ValueError, like the other account errors)."""


class SetupClosed(ValueError):
    """First-run setup was asked for, but an account already exists."""


def normalise_username(raw) -> Optional[str]:
    """The stored form of a username: trimmed, lower-case, 3 to 64 characters of letters, digits, dot, dash and underscore.
    None when the text cannot be a username. Nothing else is accepted, so a name can never be used to inject anything."""
    if not isinstance(raw, str):
        return None
    name = raw.strip().lower()
    return name if USERNAME_PATTERN.fullmatch(name) else None


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


token_id = _token_id        # public name, used by the guest session store (services/guest.py)


def csrf_for_token(token: str) -> str:
    """The CSRF token of the session that holds `token`. It is derived, not stored: the server recomputes it from the cookie on
    each request, so the database holds only the session's hash. Only someone who has the cookie can compute it."""
    return hashlib.sha256(("csrf:" + token).encode("utf-8")).hexdigest()


def _checked_new_account(username: str, role: str, password: str) -> str:
    """The stored username for a new account, or ValueError with a plain message (which never repeats the password)."""
    name = normalise_username(username)
    if name is None:
        raise ValueError("A username is 3 to 64 characters: letters, digits, '.', '-' or '_', starting with a letter or digit.")
    if name in RESERVED_USERNAMES:
        raise ValueError("That username is reserved.")
    if role not in ROLES:
        raise ValueError(f"The role must be one of: {', '.join(ROLES)}.")
    problem = password_policy_error(password)
    if problem:
        raise ValueError(problem)
    return name


def create_user(db: Session, username: str, role: str, password: str) -> UserAccount:
    """Creates an account. Raises ValueError with a plain message for any problem. The password is hashed, never stored as given."""
    name = _checked_new_account(username, role, password)
    if db.query(UserAccount).filter(UserAccount.username == name).first() is not None:
        raise AccountExists("That username already exists.")
    user = UserAccount(username=name, password_hash=hash_password(password), role=role, is_active=True, created_at=utc_now())
    db.add(user)
    db.commit()
    return user


def setup_required(db: Session) -> bool:
    """True while the user_accounts table is empty. A disabled account counts: once any account exists, setup is closed."""
    return db.query(UserAccount.id).first() is None


def create_first_approver(db: Session, username: str, password: str, now: Optional[datetime] = None) -> UserAccount:
    """Creates the first account, an approver, but only while no account exists. Raises SetupClosed when one does, and ValueError
    (a plain message that never repeats the password) when the username or password is refused.

    The existence check and the insert are ONE statement (INSERT ... SELECT ... WHERE NOT EXISTS), and the lock below also keeps two
    requests of this process apart, so two simultaneous requests cannot both create an account. The cheap check comes first so that
    a caller cannot make the server hash passwords after setup is closed."""
    if not setup_required(db):
        raise SetupClosed("Setup is already complete.")
    name = _checked_new_account(username, "approver", password)
    hashed = hash_password(password)
    now = now or utc_now()
    row = select(literal(name), literal(hashed), literal("approver"), literal(True, Boolean), literal(now, DateTime)) \
        .where(~exists(select(UserAccount.id)))
    with _RULES_LOCK:
        result = db.execute(insert(UserAccount).from_select(["username", "password_hash", "role", "is_active", "created_at"], row))
        if result.rowcount != 1:
            db.rollback()
            raise SetupClosed("Setup is already complete.")
        db.commit()
    return db.query(UserAccount).filter(UserAccount.username == name).one()


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


def list_users(db: Session) -> List[UserAccount]:
    """Every account, by username. The caller must not return password_hash to anyone."""
    return db.query(UserAccount).order_by(UserAccount.username).all()


def change_active(db: Session, acting_username: Optional[str], username: str, active: bool,
                  now: Optional[datetime] = None) -> Tuple[UserAccount, int, bool]:
    """Enables or disables an account on behalf of a signed-in approver. Returns (account, sessions ended, changed).

    Asking for the state the account already has changes nothing. Raises ValueError when no account has that name, and
    AccountRuleError when a rule refuses: nobody may disable their own account, and the last active approver cannot be disabled,
    because nobody could then manage accounts or approve a response."""
    name = normalise_username(username)
    with _RULES_LOCK:
        user = db.query(UserAccount).filter(UserAccount.username == name).first() if name else None
        if user is None:
            raise ValueError("No account has that username.")
        if bool(user.is_active) == bool(active):
            return user, 0, False
        if not active:
            if acting_username is not None and user.username == acting_username:
                raise AccountRuleError("You cannot disable your own account.")
            if user.role == "approver":
                others = db.query(UserAccount).filter(UserAccount.role == "approver", UserAccount.is_active.is_(True),
                                                      UserAccount.id != user.id).count()
                if others == 0:
                    raise AccountRuleError("The last active approver cannot be disabled, because nobody could then manage "
                                           "accounts or approve responses.")
        open_sessions = 0
        if not active:
            open_sessions = db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).count()
        set_active(db, user.username, active, now)
        return user, open_sessions, True


def verify_current_password(db: Session, user: UserAccount, password, client_ip: str, now: Optional[datetime] = None) -> str:
    """Checks the password of an account that is already signed in, before a password change. Returns "ok", "locked" or
    "bad_credentials". A wrong password counts towards the same lockout as a wrong sign-in for this name and address."""
    now = now or utc_now()
    if locked_until(db, user.username, client_ip, now) is not None:
        return "locked"
    if not isinstance(password, str) or not password or len(password) > MAX_PASSWORD_LENGTH:
        verify_unknown_user("")                 # refused before any hashing, with the same dummy work as elsewhere
        matches = False
    else:
        matches = verify_password(password, user.password_hash)
    if not matches:
        _record_failure(db, user.username, client_ip, now)
        return "bad_credentials"
    _clear_failures(db, user.username, client_ip)
    return "ok"


def change_password(db: Session, user: UserAccount, current_password: str, new_password: str, keep_session_id: Optional[str],
                    now: Optional[datetime] = None) -> int:
    """Sets a new password and ends every other open session of the account; the session `keep_session_id` stays open. Returns
    how many other sessions were ended. Raises ValueError with the reason when the new password is refused (the message never
    contains a password). The current password must already have been checked, and the caller commits, so the audit entry and
    the change are saved together."""
    now = now or utc_now()
    problem = password_policy_error(new_password)
    if problem:
        raise ValueError(problem)
    if new_password == current_password:
        raise ValueError("The new password must be different from the current one.")
    user.password_hash = hash_password(new_password)
    ended = 0
    for row in db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)):
        if row.id == keep_session_id:
            continue
        row.revoked_at = now
        row.revoke_reason = "password_changed"
        ended += 1
    db.flush()
    return ended


def reset_password(db: Session, acting_username: Optional[str], username: str, new_password: str,
                   now: Optional[datetime] = None) -> Tuple[UserAccount, int]:
    """Sets a new password for another account on behalf of an approver, ends EVERY open session of that account, and clears its
    sign-in lockout (so the person can use the new password at once). Returns (account, sessions ended).

    Raises AccountNotFound when no account has that name, ValueError when the new password is refused, and AccountRuleError when the account is the
    approver's own: an approver changes their own password with change_password, which asks for the current one. The caller
    commits, so the audit entry and the change are saved together. The message never contains a password."""
    now = now or utc_now()
    name = normalise_username(username)
    user = db.query(UserAccount).filter(UserAccount.username == name).first() if name else None
    if user is None:
        raise AccountNotFound("No account has that username.")
    if acting_username is not None and user.username == acting_username:
        raise AccountRuleError("Use Change password for your own account: it asks for your current password.")
    problem = password_policy_error(new_password)
    if problem:
        raise ValueError(problem)
    user.password_hash = hash_password(new_password)
    ended = 0
    for row in db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)):
        row.revoked_at = now
        row.revoke_reason = "password_reset"
        ended += 1
    db.query(LoginAttempt).filter(LoginAttempt.username == user.username).delete(synchronize_session=False)
    db.flush()
    return user, ended


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
