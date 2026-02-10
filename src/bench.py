"""
bench.py - Benchmark authentication and encryption/decryption costs.

Responsibilities:
- Measure Argon2 verify time
- Measure AESGCM encrypt/decrypt time as payload size increases
- Return results in structured dicts for printing/reporting
"""

from __future__ import annotations

import os
import time
import statistics
from typing import Dict, List, Any

from . import auth
from . import crypto_store


def _time_ms(fn, rounds: int) -> float:
    timings = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        timings.append((t1 - t0) * 1000.0)
    return float(statistics.median(timings))


def bench_auth_verify(stored_hash: str, secret: str, rounds: int = 20) -> Dict[str, Any]:
    """Benchmark Argon2 verification time."""
    ms = _time_ms(lambda: auth.verify_secret(stored_hash, secret), rounds)
    return {"metric": "argon2_verify_median_ms", "rounds": rounds, "value": ms}


def bench_crypto_sizes(secret: str, salt: bytes, sizes: List[int], rounds: int = 20) -> List[Dict[str, Any]]:
    """
    Benchmark encrypt/decrypt times for different payload sizes.
    Payload is a shift dict with a 'notes' field sized to N bytes.
    """
    key = crypto_store.derive_key(secret, salt)
    username = "bench_user"
    aad = username.encode("utf-8")

    results: List[Dict[str, Any]] = []
    for n in sizes:
        shift = {
            "username": username,
            "task": "bench",
            "location": "bench",
            "start": 0,
            "end": 1,
            "notes": "A" * n,
        }

        def enc():
            crypto_store.encrypt_shift(shift, key, aad)

        # Pre-generate one ciphertext for decrypt benchmark
        nonce, ciphertext = crypto_store.encrypt_shift(shift, key, aad)

        def dec():
            crypto_store.decrypt_shift(nonce, ciphertext, key, aad)

        enc_ms = _time_ms(enc, rounds)
        dec_ms = _time_ms(dec, rounds)

        results.append(
            {
                "size_bytes": n,
                "encrypt_median_ms": enc_ms,
                "decrypt_median_ms": dec_ms,
                "rounds": rounds,
            }
        )

    return results
