"""Tables for the accounts mode: user accounts, login sessions and failed-login counters (see docs/SECURITY.md).

- user_accounts: one row per person. The password is stored only as a scrypt hash (app/services/passwords.py).
- auth_sessions: one row per login. The primary key is the SHA-256 of the session token, so a copy of this table cannot be
  used to log in. The CSRF token is not stored: it is derived from the session token (app/services/accounts.csrf_for_token).
- login_attempts: failed-login counter per (username, client address). It is in the database, not in memory, so the lock
  applies across worker processes.
"""
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint

from app.models.base import Base


class UserAccount(Base):
    __tablename__ = "user_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False)          # viewer | analyst | approver
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(String(64), primary_key=True)          # SHA-256 hex of the session token; the token itself is never stored
    user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    absolute_expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoke_reason = Column(String(32), nullable=True)  # logout | expired | disabled | superseded


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    __table_args__ = (UniqueConstraint("username", "client_ip", name="uq_login_attempt_pair"),
                      Index("ix_login_attempts_last_failure", "last_failure_at"))

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False)      # as typed (normalised), whether or not the account exists
    client_ip = Column(String(64), nullable=False)
    failures = Column(Integer, nullable=False, default=0)
    last_failure_at = Column(DateTime, nullable=True)
    locked_until = Column(DateTime, nullable=True)
