"""Password hashing for the accounts mode: parameters, salts, verification, bounds and the password policy.

Each real hash costs about half a second and about 128 MiB, so the tests keep the number of hashes small."""
import base64

import pytest

from app.services import passwords as pw

GOOD = "correct horse battery"          # 20 characters, above the minimum


@pytest.fixture(scope="module")
def stored():
    return pw.hash_password(GOOD)


def test_the_hash_records_the_approved_scrypt_parameters(stored):
    prefix, n, r, p, salt, digest = stored.split("$")
    assert prefix == "scrypt"
    assert (int(n), int(r), int(p)) == (2 ** 17, 8, 1)
    assert len(base64.b64decode(salt)) == pw.SALT_BYTES
    assert len(base64.b64decode(digest)) == pw.SCRYPT_DKLEN


def test_the_plaintext_password_is_never_part_of_the_stored_value(stored):
    assert GOOD not in stored


def test_the_same_password_gets_a_different_salt_every_time(stored):
    other = pw.hash_password(GOOD)
    assert other != stored
    assert stored.split("$")[4] != other.split("$")[4]


def test_the_right_password_verifies_and_a_wrong_one_does_not(stored):
    assert pw.verify_password(GOOD, stored) is True
    assert pw.verify_password(GOOD + "!", stored) is False
    assert pw.verify_password("", stored) is False


def test_unicode_passwords_round_trip(stored):
    unicode_password = "pässwörd-ünïcödé-密码-12"
    assert pw.verify_password(unicode_password, pw.hash_password(unicode_password))


@pytest.mark.parametrize("stored_value", [
    "", "not-a-hash", "scrypt$1$2$3", "bcrypt$131072$8$1$AAAA$AAAA", "scrypt$x$8$1$AAAA$AAAA",
    "scrypt$131072$8$1$!!!$AAAA", "scrypt$131071$8$1$AAAA$AAAA",       # N must be a power of two
])
def test_malformed_stored_values_never_verify(stored_value):
    assert pw.verify_password(GOOD, stored_value) is False


def test_out_of_bounds_parameters_are_refused_without_running_the_hash():
    huge = f"scrypt${2 ** 30}$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAA=="
    assert pw.verify_password(GOOD, huge) is False          # returns at once; it would otherwise need terabytes


def test_a_tampered_digest_does_not_verify(stored):
    prefix, n, r, p, salt, digest = stored.split("$")
    raw = bytearray(base64.b64decode(digest))
    raw[0] ^= 0x01
    tampered = f"{prefix}${n}${r}${p}${salt}${base64.b64encode(bytes(raw)).decode()}"
    assert pw.verify_password(GOOD, tampered) is False


def test_the_dummy_check_for_unknown_users_always_refuses():
    assert pw.verify_unknown_user(GOOD) is False


@pytest.mark.parametrize("candidate,reason", [
    ("short", "at least 12"),
    ("   " * 6, "only spaces"),
    ("x" * (pw.MAX_PASSWORD_LENGTH + 1), "at most"),
    (None, "must be text"),
])
def test_the_password_policy_refuses_weak_and_oversized_passwords(candidate, reason):
    message = pw.password_policy_error(candidate)
    assert message is not None and reason in message


def test_the_password_policy_accepts_a_long_enough_password_and_never_echoes_it():
    assert pw.password_policy_error(GOOD) is None
    message = pw.password_policy_error("short-one")
    assert "short-one" not in message


def test_the_concurrency_limit_is_a_small_bounded_semaphore():
    # two slots: a third concurrent hash waits instead of exhausting memory
    acquired = [pw._HASH_SLOTS.acquire(blocking=False) for _ in range(3)]
    try:
        assert acquired == [True, True, False]
    finally:
        for got in acquired:
            if got:
                pw._HASH_SLOTS.release()
