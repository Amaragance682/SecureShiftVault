"""
crypto_store.py - Encryption at rest for shift data.

Responsibilities:
- Derive a per-user encryption key from their secret + stored KDF salt
- Encrypt and decrypt shift payloads using AEAD (AES-256-GCM)

Design notes:
- We store a per-user kdf_salt in the users table.
- We derive a 32-byte key using Scrypt (memory-hard KDF).
- We encrypt each shift payload JSON with AESGCM using a fresh 12-byte nonce.
- We bind ciphertext to the username using AAD (Additional Authenticated Data),
  so records cannot be trivially swapped between users without detection.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Scrypt parameters
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # AES-256


def new_kdf_salt() -> bytes:
    """Generate a new per-user salt for key derivation."""
    return os.urandom(16)


def derive_key(secret: str, salt: bytes) -> bytes:
    """Derive a stable encryption key from user secret and per-user salt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(secret.encode("utf-8"))


def encrypt_shift(shift: Dict[str, Any], key: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt a shift dict to (nonce, ciphertext).
    AESGCM ciphertext includes the auth tag.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    plaintext = json.dumps(shift, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_shift(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes) -> Dict[str, Any]:
    """Decrypt (nonce, ciphertext) back into a dict. Raises on auth failure."""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return json.loads(plaintext.decode("utf-8"))
