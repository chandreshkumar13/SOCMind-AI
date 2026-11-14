"""Password hashing for the accounts mode (see docs/SECURITY.md).

scrypt from the standard library, with N=2^17, r=8, p=1 (OWASP's recommended work factor for scrypt). Each hash uses its own
random salt, and the parameters are stored with the hash, so they can be raised later without breaking existing accounts.

Costs, measured on the development machine (see the commit message and docs): about 0.5 s and about 128 MiB of memory per hash.
Because the memory is large, concurrent hashing is capped by a semaphore. A login waits for a slot instead of exhausting memory.
The cap is per process; with several worker processes the total is the cap multiplied by the number of workers.

Nothing here reads a default or hard-coded password. Passwords are only ever passed in by the caller.
"""
import base64
import hashlib
import hmac
import secrets
import threading
from typing import Optional

SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16
# scrypt needs about 128 * N * r bytes of memory; hashlib refuses more than its 32 MiB default, so the limit is set explicitly.
SCRYPT_MAXMEM = 256 * 1024 * 1024

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024        # bounds the work a single attempt can ask for

# Bounds for parameters read back from storage. A stored hash that asks for more is refused rather than run.
_MAX_STORED_N = 2 ** 20
_MAX_STORED_R = 32
_MAX_STORED_P = 4

_PREFIX = "scrypt"
_HASH_SLOTS = threading.BoundedSemaphore(2)   # at most two hashes at a time per process
_dummy_lock = threading.Lock()
_dummy_hash: Optional[str] = None


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    maxmem = max(SCRYPT_MAXMEM, 128 * n * r + 1024 * 1024)
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=SCRYPT_DKLEN)


def password_policy_error(password: str) -> Optional[str]:
    """None when the password may be used, otherwise the reason in plain words. Never echoes the password."""
    if not isinstance(password, str):
        return "The password must be text."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"The password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"The password must be at most {MAX_PASSWORD_LENGTH} characters long."
    if not password.strip():
        return "The password cannot be only spaces."
    return None


def hash_password(password: str) -> str:
    """A storable string: scrypt$N$r$p$salt$hash, with the salt and hash in base64. A new random salt on every call."""
    salt = secrets.token_bytes(SALT_BYTES)
    with _HASH_SLOTS:
        digest = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    b64 = lambda raw: base64.b64encode(raw).decode("ascii")
    return f"{_PREFIX}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """True only when the password matches the stored hash. A malformed or out-of-bounds stored value is simply False."""
    try:
        prefix, n_text, r_text, p_text, salt_text, hash_text = stored.split("$")
        if prefix != _PREFIX:
            return False
        n, r, p = int(n_text), int(r_text), int(p_text)
        if not (2 <= n <= _MAX_STORED_N and n & (n - 1) == 0 and 1 <= r <= _MAX_STORED_R and 1 <= p <= _MAX_STORED_P):
            return False
        salt = base64.b64decode(salt_text, validate=True)
        expected = base64.b64decode(hash_text, validate=True)
    except (ValueError, TypeError, AttributeError):
        return False
    with _HASH_SLOTS:
        actual = _derive(password, salt, n, r, p)
    return hmac.compare_digest(actual, expected)


def _dummy() -> str:
    """A real hash of a value nobody knows, computed once per process. Checked against when a username does not exist, so that
    an unknown name takes as long to refuse as a wrong password, and the response reveals nothing about which names exist."""
    global _dummy_hash
    with _dummy_lock:
        if _dummy_hash is None:
            _dummy_hash = hash_password(secrets.token_urlsafe(24))
        return _dummy_hash


def verify_unknown_user(password: str) -> bool:
    """Spends the same time as verify_password for a real account, then returns False."""
    verify_password(password, _dummy())
    return False
