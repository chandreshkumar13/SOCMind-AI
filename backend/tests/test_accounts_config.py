"""Startup rules for AUTH_MODE=accounts (see docs/SECURITY.md). Pure configuration checks: no database, no server."""
import pytest

from app.core.auth import session_cookie_secure, validate_auth_config
from app.core.config import settings

GOOD_TOKEN = {"name": "Automation", "role": "analyst", "token": "a-static-token-for-automation-123"}


def test_accounts_mode_starts_in_production_with_no_static_tokens():
    validate_auth_config("accounts", [], "production", cookie_secure=True)


def test_accounts_mode_with_valid_static_tokens_starts():
    validate_auth_config("accounts", [GOOD_TOKEN], "production", cookie_secure=True)


def test_a_malformed_static_token_is_refused_in_accounts_mode_too():
    with pytest.raises(ValueError, match="at least 16"):
        validate_auth_config("accounts", [{"name": "x", "role": "viewer", "token": "short"}], "production")


def test_insecure_session_cookies_are_refused_in_production():
    with pytest.raises(ValueError, match="SESSION_COOKIE_SECURE=false is refused"):
        validate_auth_config("accounts", [], "production", cookie_secure=False)


def test_insecure_session_cookies_are_allowed_only_for_development_and_test():
    validate_auth_config("accounts", [], "development", cookie_secure=False)
    validate_auth_config("accounts", [], "test", cookie_secure=False)


def test_demo_mode_is_still_refused_in_production():
    with pytest.raises(ValueError, match="AUTH_MODE=disabled is refused"):
        validate_auth_config("disabled", [], "production")


def test_an_unknown_mode_is_refused_and_the_message_lists_the_three_modes():
    with pytest.raises(ValueError, match="'disabled', 'token' or 'accounts'"):
        validate_auth_config("sso", [], "production")


def test_the_cookie_is_secure_by_default_outside_development(monkeypatch):
    monkeypatch.setattr(settings, "SESSION_COOKIE_SECURE", None)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    assert session_cookie_secure() is True
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    assert session_cookie_secure() is False


def test_an_explicit_setting_overrides_the_default(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SESSION_COOKIE_SECURE", False)
    assert session_cookie_secure() is False


def test_the_defaults_match_the_approved_policy():
    assert settings.SESSION_IDLE_MINUTES == 30
    assert settings.SESSION_ABSOLUTE_HOURS == 8
    assert settings.LOGIN_MAX_FAILURES == 5
    assert settings.LOGIN_LOCK_MINUTES == 15
