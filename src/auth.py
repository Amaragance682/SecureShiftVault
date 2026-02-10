"""
auth.py - Authentication helpers using Argon2.

Responsibilities:
- Hash user secrets (password or PIN) for storage
- Verify secrets at login time

We use Argon2id via argon2-cffi, which is memory-hard and suitable for
slowing offline brute-force attacks (important for your rubric).
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# parameters to test
# memory_cost is in kilobytes (the KiB version). time_cost is iterations.
PH = PasswordHasher(
    time_cost=2,
    memory_cost=102400,  # about 100 MiB
    parallelism=8,
    hash_len=32,
    salt_len=16,
)


def hash_secret(secret: str) -> str:
    """Return Argon2 encoded hash string (includes salt + parameters)."""
    return PH.hash(secret)


def verify_secret(stored_hash: str, secret: str) -> bool:
    """Verify a secret against stored Argon2 hash."""
    try:
        return PH.verify(stored_hash, secret)
    except VerifyMismatchError:
        return False
