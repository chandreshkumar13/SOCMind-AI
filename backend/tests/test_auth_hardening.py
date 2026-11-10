"""Hardening of the authentication configuration (final review, items 2 and 6).

Demo mode must not be reachable from a production-like environment, and a token configuration must be unambiguous: unique,
header-safe and never echoed back in an error message."""
import pytest

from app.core.auth import validate_auth_config
from app.core.config import Settings

GOOD = "a-good-random-token-0123456789"


def entry(name="Ana Analyst", role="analyst", token=GOOD):
    return {"name": name, "role": role, "token": token}


@pytest.mark.parametrize("environment", ["production", "staging", "Production", "", "prod", "demo"])
def test_demo_mode_without_a_token_is_refused_outside_development_and_test(environment):
    with pytest.raises(ValueError, match="AUTH_MODE=disabled is refused"):
        validate_auth_config("disabled", [], environment)


@pytest.mark.parametrize("environment", ["development", "test", " Development "])
def test_demo_mode_is_still_allowed_for_development_and_test(environment):
    validate_auth_config("disabled", [], environment)


def test_the_environment_defaults_to_development_so_existing_callers_keep_working():
    validate_auth_config("disabled", [])


def test_token_mode_starts_in_production_with_a_valid_token():
    validate_auth_config("token", [entry()], "production")


def test_two_entries_with_one_token_are_refused_and_the_token_is_not_printed():
    with pytest.raises(ValueError, match="share the same token") as err:
        validate_auth_config("token", [entry("A", "viewer"), entry("B", "approver")], "production")
    assert GOOD not in str(err.value)


@pytest.mark.parametrize("bad", [
    "has a space in it 0123456789abcdef",
    "tab\there-0123456789abcdef",
    "unicode-tökén-0123456789abc",
    "trailing-newline-0123456789\n",
])
def test_tokens_must_be_printable_ascii_without_spaces(bad):
    with pytest.raises(ValueError, match="printable ASCII"):
        validate_auth_config("token", [entry(token=bad)], "production")


def test_an_entry_that_is_not_an_object_is_refused_without_echoing_it():
    with pytest.raises(ValueError, match="must be an object") as err:
        validate_auth_config("token", ["secret-looking-token-0123456789"], "production")
    assert "secret-looking-token" not in str(err.value)


def test_a_short_token_is_refused_without_echoing_it():
    with pytest.raises(ValueError, match="at least 16") as err:
        validate_auth_config("token", [entry(token="short-tok")], "production")
    assert "short-tok" not in str(err.value)


def test_a_malformed_token_list_from_the_environment_is_validated_without_echoing_the_value(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "token")
    monkeypatch.setenv("AUTH_TOKENS", '["secret-looking-token-0123456789"]')
    settings = Settings()                       # loads without raising: the shape is checked by validate_auth_config
    with pytest.raises(ValueError) as err:
        validate_auth_config(settings.AUTH_MODE, settings.AUTH_TOKENS, "production")
    assert "secret-looking-token" not in str(err.value)
