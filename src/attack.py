"""
attack.py - Offline brute-force demonstrations.

Two demo styles:
1) brute-force a PIN against Argon2 hash verification (slow by design)
2) brute-force a PIN by attempting to derive key + decrypt one ciphertext
   (clean "stolen DB file" scenario; success determined by AEAD tag)

NOTE:
- Brute-forcing Argon2 can be very slow depending on parameters.
- For report purposes, you can use a 4-digit PIN and show the observed time.
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from . import auth
from . import crypto_store


def bruteforce_pin_hash(stored_hash: str, digits: int = 4) -> Tuple[Optional[str], float, int]:
    """Try all PINs of given length against Argon2 verification."""
    start = time.perf_counter()
    attempts = 0
    max_pin = 10**digits

    for i in range(max_pin):
        pin = str(i).zfill(digits)
        attempts += 1
        if auth.verify_secret(stored_hash, pin):
            return pin, (time.perf_counter() - start), attempts

    return None, (time.perf_counter() - start), attempts


def bruteforce_pin_decrypt(
    username: str,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    digits: int = 4,
) -> Tuple[Optional[str], float, int]:
    """
    Offline brute-force: for each candidate PIN:
    - derive key
    - attempt AESGCM decrypt
    Success is unambiguous: decrypt returns without exception.
    """
    aad = username.encode("utf-8")
    start = time.perf_counter()
    attempts = 0
    max_pin = 10**digits

    for i in range(max_pin):
        pin = str(i).zfill(digits)
        attempts += 1
        key = crypto_store.derive_key(pin, salt)
        try:
            _ = crypto_store.decrypt_shift(nonce, ciphertext, key, aad)
            return pin, (time.perf_counter() - start), attempts
        except Exception:
            # Invalid tag / wrong key / corrupted data
            pass

    return None, (time.perf_counter() - start), attempts
