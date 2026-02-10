"""
app.py - CLI entrypoint

Commands list:
- init-db: create schema
- register: create user with Argon2 hash + store per-user KDF salt
- login: verify credentials
- clockin: store an encrypted shift record with end=None
- clockout: decrypt last shift, set end timestamp, re-encrypt + update
- list: decrypt and print all shifts
- bench: run timing experiments (auth + crypto sizes)
- attack: brute-force demo (hash or decrypt)
"""

from __future__ import annotations

import argparse
import getpass
import time
from typing import Any, Dict

from . import db
from . import auth
from . import crypto_store
from . import bench
from . import attack


def _prompt_secret(prompt: str = "Secret (PIN or password): ") -> str:
    return getpass.getpass(prompt)


def cmd_init_db(args: argparse.Namespace) -> None:
    conn = db.connect(args.db)
    db.init_db(conn)
    conn.close()
    print(f"OK: initialized DB at {args.db}")


def cmd_register(args: argparse.Namespace) -> None:
    conn = db.connect(args.db)
    db.init_db(conn)

    username = args.username
    secret = _prompt_secret()

    pw_hash = auth.hash_secret(secret)
    kdf_salt = crypto_store.new_kdf_salt()
    db.create_user(conn, username, pw_hash, kdf_salt)

    conn.close()
    print("OK: user registered")


def cmd_login(args: argparse.Namespace) -> None:
    conn = db.connect(args.db)
    user = db.get_user(conn, args.username)
    conn.close()

    if not user:
        print("FAIL: user not found")
        return

    stored_hash, _salt = user
    secret = _prompt_secret()

    ok = auth.verify_secret(stored_hash, secret)
    print("OK: login success" if ok else "FAIL: login failed")


def cmd_clockin(args: argparse.Namespace) -> None:
    conn = db.connect(args.db)
    user = db.get_user(conn, args.username)
    if not user:
        conn.close()
        print("FAIL: user not found")
        return

    stored_hash, kdf_salt = user
    secret = _prompt_secret()

    if not auth.verify_secret(stored_hash, secret):
        conn.close()
        print("FAIL: login failed")
        return

    key = crypto_store.derive_key(secret, kdf_salt)
    aad = args.username.encode("utf-8")

    shift: Dict[str, Any] = {
        "username": args.username,
        "task": args.task,
        "location": args.location,
        "start": int(time.time()),
        "end": None,
        "notes": args.notes or "",
    }

    nonce, ciphertext = crypto_store.encrypt_shift(shift, key, aad)
    shift_id = db.insert_shift_blob(conn, args.username, nonce, ciphertext)
    conn.close()

    print(f"OK: clock-in stored as shift id {shift_id}")


def cmd_clockout(args: argparse.Namespace) -> None:
    conn = db.connect(args.db)
    user = db.get_user(conn, args.username)
    if not user:
        conn.close()
        print("FAIL: user not found")
        return

    stored_hash, kdf_salt = user
    secret = _prompt_secret()

    if not auth.verify_secret(stored_hash, secret):
        conn.close()
        print("FAIL: login failed")
        return

    last = db.get_last_shift_blob(conn, args.username)
    if not last:
        conn.close()
        print("FAIL: no shifts found")
        return

    shift_id, nonce, ciphertext, _created_at = last
    key = crypto_store.derive_key(secret, kdf_salt)
    aad = args.username.encode("utf-8")

    try:
        shift = crypto_store.decrypt_shift(nonce, ciphertext, key, aad)
    except Exception:
        conn.close()
        print("FAIL: could not decrypt last shift (wrong key corrupted data or tampering detected)")
        return

    if shift.get("end") is not None:
        conn.close()
        print("FAIL: last shift already ended")
        return

    shift["end"] = int(time.time())
    if args.notes:
        shift["notes"] = (shift.get("notes", "") + "\n" + args.notes).strip()

    new_nonce, new_ciphertext = crypto_store.encrypt_shift(shift, key, aad)
    db.update_shift_blob(conn, shift_id, new_nonce, new_ciphertext)

    conn.close()
    print(f"OK: clock-out updated shift id {shift_id}")


def cmd_list(args: argparse.Namespace) -> None:
    conn = db.connect(args.db)
    user = db.get_user(conn, args.username)
    if not user:
        conn.close()
        print("FAIL: user not found")
        return

    stored_hash, kdf_salt = user
    secret = _prompt_secret()

    if not auth.verify_secret(stored_hash, secret):
        conn.close()
        print("FAIL: login failed")
        return
    key = crypto_store.derive_key(secret, kdf_salt)
    aad = args.username.encode("utf-8")
    rows = db.list_shift_blobs(conn, args.username)
    conn.close()

    print(f"Shifts for {args.username}: {len(rows)} record(s)\n")
    for shift_id, nonce, ciphertext, created_at in rows:
        try:
            shift = crypto_store.decrypt_shift(nonce, ciphertext, key, aad)
            print(f"- id={shift_id} created_at={created_at} start={shift.get('start')} end={shift.get('end')}")
            print(f"  task={shift.get('task')} location={shift.get('location')}")
            notes = shift.get("notes", "")
            if notes:
                print(f"  notes={notes[:80]}{'...' if len(notes) > 80 else ''}")
        except Exception:
            print(f"- id={shift_id} (FAILED TO DECRYPT)")
        print("")


def cmd_bench(args: argparse.Namespace) -> None:
    # Bench uses a synthetic user hash for auth timing.
    secret = args.secret if args.secret else "1234"
    stored_hash = auth.hash_secret(secret)

    auth_result = bench.bench_auth_verify(stored_hash, secret, rounds=args.rounds)

    # Crypto bench: we need a salt (as in real system)
    salt = crypto_store.new_kdf_salt()
    sizes = [int(x) for x in args.sizes.split(",")]

    crypto_results = bench.bench_crypto_sizes(secret, salt, sizes=sizes, rounds=args.rounds)

    print("== AUTH BENCH ==")
    print(auth_result)
    print("\n== CRYPTO BENCH PRESSURE TEST !!!==")
    for r in crypto_results:
        print(r)


def cmd_attack(args: argparse.Namespace) -> None:
    conn = db.connect(args.db)
    user = db.get_user(conn, args.username)
    if not user:
        conn.close()
        print("FAIL: user not found")
        return

    stored_hash, kdf_salt = user
    last = db.get_last_shift_blob(conn, args.username)
    conn.close()

    if not last:
        print("FAIL: no shifts found to attack")
        return

    shift_id, nonce, ciphertext, _created_at = last

    if args.mode == "hash":
        found, seconds, attempts = attack.bruteforce_pin_hash(stored_hash, digits=args.digits)
        print(f"Attack=hash digits={args.digits} attempts={attempts} seconds={seconds:.3f} found={found}")
    else:
        found, seconds, attempts = attack.bruteforce_pin_decrypt(
            args.username, kdf_salt, nonce, ciphertext, digits=args.digits
        )
        print(f"Attack=decrypt digits={args.digits} attempts={attempts} seconds={seconds:.3f} found={found}")
        print(f"(Target shift id was {shift_id})")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="SecureShiftVault")
    p.add_argument("--db", default="vault.db", help="SQLite database path")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-db", help="Initialize database schema")
    s.set_defaults(func=cmd_init_db)

    s = sub.add_parser("register", help="Register a new user")
    s.add_argument("username")
    s.set_defaults(func=cmd_register)

    s = sub.add_parser("login", help="Verify login")
    s.add_argument("username")
    s.set_defaults(func=cmd_login)

    s = sub.add_parser("clockin", help="Create encrypted shift with end=None")
    s.add_argument("username")
    s.add_argument("--task", required=True)
    s.add_argument("--location", required=True)
    s.add_argument("--notes", default="")
    s.set_defaults(func=cmd_clockin)

    s = sub.add_parser("clockout", help="End most recent shift (decrypt, update end, re-encrypt)")
    s.add_argument("username")
    s.add_argument("--notes", default="")
    s.set_defaults(func=cmd_clockout)

    s = sub.add_parser("list", help="Decrypt and list shifts")
    s.add_argument("username")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("bench", help="Run benchmarks")
    s.add_argument("--rounds", type=int, default=20)
    s.add_argument("--sizes", default="1024,10240,102400,1048576", help="Comma-separated sizes in bytes")
    s.add_argument("--secret", default="", help="Optional fixed secret for bench (default uses '1234')")
    s.set_defaults(func=cmd_bench)

    s = sub.add_parser("attack", help="Run offline brute-force demo against last shift")
    s.add_argument("username")
    s.add_argument("--mode", choices=["hash", "decrypt"], default="decrypt")
    s.add_argument("--digits", type=int, default=4)
    s.set_defaults(func=cmd_attack)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
