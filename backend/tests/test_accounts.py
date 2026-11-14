"""Accounts service: user creation, sign-in with lockout, disabled users and sessions (idle timeout, absolute lifetime, revocation).

Each test gets its own database file in tmp_path, built here. The clock is passed in explicitly, so no test sleeps. A real
password hash costs about half a second, so the tests create only the accounts they need."""
import hashlib
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.auth_models import AuthSession, LoginAttempt, UserAccount
from app.models.base import Base
from app.services import accounts
from app.services import passwords as pw

PASSWORD = "a long enough passphrase"
T0 = datetime(2026, 11, 10, 9, 0, 0)
IP = "203.0.113.7"


@pytest.fixture
def db(tmp_path):
    import app.models.models  # noqa: F401  (register every table)
    engine = create_engine(f"sqlite:///{tmp_path / 'accounts.db'}".replace("\\", "/"), connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def ana(db):
    return accounts.create_user(db, "Ana.Analyst", "analyst", PASSWORD)


# ----------------------------------------------------------------------------------- creating accounts
def test_usernames_are_normalised_and_limited():
    assert accounts.normalise_username("  Ana.Analyst  ") == "ana.analyst"
    assert accounts.normalise_username("ab") is None                       # too short
    assert accounts.normalise_username("a" * 65) is None                   # too long
    assert accounts.normalise_username("ana; drop table") is None          # no spaces or symbols
    assert accounts.normalise_username("<script>") is None
    assert accounts.normalise_username(None) is None


def test_an_account_stores_a_hash_and_never_the_password(db, ana):
    stored = db.get(UserAccount, ana.id)
    assert stored.username == "ana.analyst" and stored.role == "analyst" and stored.is_active is True
    assert stored.password_hash.startswith("scrypt$")
    assert PASSWORD not in stored.password_hash
    assert pw.verify_password(PASSWORD, stored.password_hash)


def test_the_role_and_the_password_policy_are_enforced(db):
    with pytest.raises(ValueError, match="role must be one of"):
        accounts.create_user(db, "x-role", "root", PASSWORD)
    with pytest.raises(ValueError, match="at least 12"):
        accounts.create_user(db, "x-short", "viewer", "short")
    with pytest.raises(ValueError, match="username"):
        accounts.create_user(db, "no", "viewer", PASSWORD)


def test_a_duplicate_username_is_refused_in_any_letter_case(db, ana):
    with pytest.raises(ValueError, match="already exists"):
        accounts.create_user(db, "ANA.ANALYST", "viewer", PASSWORD)


# ----------------------------------------------------------------------------------- sign-in
def test_the_right_password_signs_in_and_the_wrong_one_does_not(db, ana):
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, IP, now=T0)[0] == "ok"
    assert accounts.authenticate(db, "ana.analyst", PASSWORD + "x", IP, now=T0)[0] == "bad_credentials"


def test_an_unknown_name_gets_the_same_answer_and_is_checked_with_the_same_work(db, ana, monkeypatch):
    calls = []
    real = pw.verify_password
    monkeypatch.setattr(accounts, "verify_password", lambda p, s: calls.append("real") or real(p, s))
    monkeypatch.setattr(accounts, "verify_unknown_user", lambda p: calls.append("dummy") or False)
    assert accounts.authenticate(db, "nobody-here", PASSWORD, IP, now=T0) == ("bad_credentials", None)
    assert accounts.authenticate(db, "ana.analyst", "wrong-wrong-wrong", IP, now=T0)[0] == "bad_credentials"
    assert calls == ["dummy", "real"], "an unknown name must spend the same kind of work as a real account"


def test_an_oversized_or_non_text_password_is_refused_before_any_hashing(db, ana, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no hashing for a refused input")
    monkeypatch.setattr(accounts, "verify_password", boom)
    monkeypatch.setattr(accounts, "verify_unknown_user", lambda p: False)
    assert accounts.authenticate(db, "ana.analyst", "x" * (pw.MAX_PASSWORD_LENGTH + 1), IP, now=T0)[0] == "bad_credentials"
    assert accounts.authenticate(db, "ana.analyst", None, IP, now=T0)[0] == "bad_credentials"
    assert accounts.authenticate(db, "ana.analyst", "", IP, now=T0)[0] == "bad_credentials"


# ----------------------------------------------------------------------------------- lockout
def test_five_failures_lock_the_pair_even_for_the_right_password(db, ana):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert accounts.authenticate(db, "ana.analyst", "wrong-wrong-wrong", IP, now=T0)[0] == "bad_credentials"
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, IP, now=T0)[0] == "locked"


def test_the_lock_lasts_fifteen_minutes_and_then_lifts(db, ana):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        accounts.authenticate(db, "ana.analyst", "wrong-wrong-wrong", IP, now=T0)
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, IP, now=T0 + timedelta(minutes=14))[0] == "locked"
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, IP, now=T0 + timedelta(minutes=16))[0] == "ok"


def test_four_failures_do_not_lock_and_a_success_clears_the_count(db, ana):
    for _ in range(settings.LOGIN_MAX_FAILURES - 1):
        accounts.authenticate(db, "ana.analyst", "wrong-wrong-wrong", IP, now=T0)
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, IP, now=T0)[0] == "ok"
    assert db.query(LoginAttempt).filter(LoginAttempt.username == "ana.analyst").count() == 0
    for _ in range(settings.LOGIN_MAX_FAILURES - 1):
        assert accounts.authenticate(db, "ana.analyst", "wrong-wrong-wrong", IP, now=T0)[0] == "bad_credentials"


def test_failures_spread_over_more_than_the_window_do_not_add_up_to_a_lock(db, ana):
    step = timedelta(minutes=settings.LOGIN_LOCK_MINUTES + 1)
    for i in range(settings.LOGIN_MAX_FAILURES + 2):
        accounts.authenticate(db, "ana.analyst", "wrong-wrong-wrong", IP, now=T0 + i * step)
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, IP, now=T0 + 10 * step)[0] == "ok"


def test_the_lock_is_per_username_and_per_client_address(db, ana):
    accounts.create_user(db, "ben.builder", "viewer", PASSWORD)
    for _ in range(settings.LOGIN_MAX_FAILURES):
        accounts.authenticate(db, "ana.analyst", "wrong-wrong-wrong", IP, now=T0)
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, "198.51.100.9", now=T0)[0] == "ok"       # another address
    assert accounts.authenticate(db, "ben.builder", PASSWORD, IP, now=T0)[0] == "ok"                   # another name


def test_the_lock_applies_to_names_that_do_not_exist_so_it_reveals_nothing(db):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        accounts.authenticate(db, "no-such-person", "wrong-wrong-wrong", IP, now=T0)
    assert accounts.authenticate(db, "no-such-person", "wrong-wrong-wrong", IP, now=T0)[0] == "locked"


# ----------------------------------------------------------------------------------- disabled users
def test_a_disabled_account_cannot_sign_in_even_with_the_right_password(db, ana):
    accounts.set_active(db, "ana.analyst", False, now=T0)
    assert accounts.authenticate(db, "ana.analyst", PASSWORD, IP, now=T0) == ("bad_credentials", None)


def test_disabling_an_account_ends_its_open_sessions_at_once(db, ana):
    token, row = accounts.create_session(db, ana, now=T0)
    assert accounts.session_for_token(db, token, now=T0) is not None
    accounts.set_active(db, "ana.analyst", False, now=T0 + timedelta(minutes=1))
    assert accounts.session_for_token(db, token, now=T0 + timedelta(minutes=2)) is None
    assert db.get(AuthSession, row.id).revoke_reason == "disabled"


def test_re_enabling_does_not_bring_back_a_session_that_was_ended(db, ana):
    token, _ = accounts.create_session(db, ana, now=T0)
    accounts.set_active(db, "ana.analyst", False, now=T0)
    accounts.set_active(db, "ana.analyst", True, now=T0)
    assert accounts.session_for_token(db, token, now=T0) is None


# ----------------------------------------------------------------------------------- sessions
def test_only_a_hash_of_the_session_token_is_stored(db, ana):
    token, row = accounts.create_session(db, ana, now=T0)
    assert row.id == hashlib.sha256(token.encode()).hexdigest()
    assert token not in row.id
    assert len(accounts.csrf_for_token(token)) == 64 and accounts.csrf_for_token(token) != token
    assert not hasattr(row, "csrf_token"), "the CSRF value is derived from the cookie, never stored"


def test_each_session_gets_its_own_csrf_token(db, ana):
    first_token, _ = accounts.create_session(db, ana, now=T0)
    second_token, _ = accounts.create_session(db, ana, now=T0)
    assert accounts.csrf_for_token(first_token) != accounts.csrf_for_token(second_token)


def test_a_session_that_is_used_stays_alive_and_one_left_alone_for_thirty_minutes_ends(db, ana):
    token, _ = accounts.create_session(db, ana, now=T0)
    idle = timedelta(minutes=settings.SESSION_IDLE_MINUTES)
    step = timedelta(minutes=20)
    assert accounts.session_for_token(db, token, now=T0 + step) is not None          # 20 min later: still fine
    assert accounts.session_for_token(db, token, now=T0 + 2 * step) is not None      # 20 min after that: still fine
    assert accounts.session_for_token(db, token, now=T0 + 2 * step + idle + timedelta(seconds=1)) is None


def test_the_idle_limit_is_thirty_minutes_by_default():
    assert settings.SESSION_IDLE_MINUTES == 30


def test_a_session_ends_eight_hours_after_sign_in_even_while_in_use(db, ana):
    token, row = accounts.create_session(db, ana, now=T0)
    assert row.absolute_expires_at == T0 + timedelta(hours=8)
    now = T0
    while now < T0 + timedelta(hours=8):
        now += timedelta(minutes=10)                       # keeps the session busy, so only the absolute limit can end it
        found = accounts.session_for_token(db, token, now=now)
        if now >= T0 + timedelta(hours=8):
            assert found is None
        else:
            assert found is not None


def test_logging_out_ends_only_that_session(db, ana):
    token_a, row_a = accounts.create_session(db, ana, now=T0)
    token_b, _ = accounts.create_session(db, ana, now=T0)
    accounts.end_session(db, row_a, reason="logout", now=T0)
    assert accounts.session_for_token(db, token_a, now=T0) is None
    assert accounts.session_for_token(db, token_b, now=T0) is not None
    assert db.get(AuthSession, row_a.id).revoke_reason == "logout"


def test_an_unknown_or_empty_token_is_not_a_session(db, ana):
    assert accounts.session_for_token(db, "", now=T0) is None
    assert accounts.session_for_token(db, "not-a-real-token", now=T0) is None


def test_the_idle_timeout_and_lifetime_come_from_settings(db, ana, monkeypatch):
    monkeypatch.setattr(settings, "SESSION_IDLE_MINUTES", 5)
    token, _ = accounts.create_session(db, ana, now=T0)
    assert accounts.session_for_token(db, token, now=T0 + timedelta(minutes=6)) is None


def test_set_active_refuses_an_unknown_account(db):
    with pytest.raises(ValueError, match="No account"):
        accounts.set_active(db, "nobody-here", False, now=T0)
