"""Schema of the accounts tables. Runs only on the throw-away test database that conftest.py sets up, never on socmind.db."""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.db.session import SessionLocal, engine
from app.models.auth_models import AuthSession, LoginAttempt, UserAccount


def test_the_accounts_tables_are_created_by_init_db():
    names = set(inspect(engine).get_table_names())
    assert {"user_accounts", "auth_sessions", "login_attempts"} <= names


def test_the_session_table_has_no_column_that_could_hold_a_raw_token():
    columns = {c["name"] for c in inspect(engine).get_columns("auth_sessions")}
    assert columns == {"id", "user_id", "created_at", "last_seen_at", "absolute_expires_at", "revoked_at", "revoke_reason"}
    assert "token" not in columns and "csrf_token" not in columns


def test_usernames_are_unique():
    db = SessionLocal()
    try:
        db.add(UserAccount(username="schema-unique", password_hash="x", role="viewer"))
        db.commit()
        db.add(UserAccount(username="schema-unique", password_hash="y", role="analyst"))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.query(UserAccount).filter(UserAccount.username == "schema-unique").delete()
        db.commit()
        db.close()


def test_a_session_belongs_to_a_user_and_records_the_absolute_expiry():
    db = SessionLocal()
    try:
        user = UserAccount(username="schema-session", password_hash="x", role="approver")
        db.add(user)
        db.commit()
        expires = datetime.utcnow() + timedelta(hours=8)
        db.add(AuthSession(id="a" * 64, user_id=user.id, absolute_expires_at=expires))
        db.commit()
        stored = db.get(AuthSession, "a" * 64)
        assert stored.user_id == user.id and stored.revoked_at is None
        assert stored.absolute_expires_at == expires
    finally:
        db.query(AuthSession).filter(AuthSession.id == "a" * 64).delete()
        db.query(UserAccount).filter(UserAccount.username == "schema-session").delete()
        db.commit()
        db.close()


def test_login_attempts_are_unique_per_username_and_client_address():
    db = SessionLocal()
    try:
        db.add(LoginAttempt(username="schema-attempt", client_ip="10.0.0.1", failures=1))
        db.commit()
        db.add(LoginAttempt(username="schema-attempt", client_ip="10.0.0.1", failures=2))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        db.add(LoginAttempt(username="schema-attempt", client_ip="10.0.0.2", failures=1))   # another address is its own pair
        db.commit()
    finally:
        db.rollback()
        db.query(LoginAttempt).filter(LoginAttempt.username == "schema-attempt").delete()
        db.commit()
        db.close()
