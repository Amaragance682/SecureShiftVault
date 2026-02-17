# intentionally sniffable plaintext server

from __future__ import annotations

import os
import socket
import time
import secrets
from typing import Any, Dict, Optional, Tuple

from .net_protocol import send_msg, recv_msg
from . import db, auth, crypto_store

# may need to change these 
HOST = "127.0.0.1"
PORT = 5000

# In-memory sessions
SESSIONS: Dict[str, Tuple[str, float]] = {}
SESSION_TTL_SECONDS = 30 * 60

def _issue_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = (username, time.time() + SESSION_TTL_SECONDS)
    return token

def _get_username_from_token(token: str) -> Optional[str]:
    row = SESSIONS.get(token)
    if not row:
        return None
    username, exp = row
    if time.time() > exp:
        SESSIONS.pop(token, None)
        return None
    return username

def handle_request(req: Dict[str, Any], db_path: str) -> Dict[str, Any]:
    cmd = req.get("cmd")
    conn = db.connect(db_path)
    db.init_db(conn)

    try:
        if cmd == "register":
            username = req["username"]
            pin = req["pin"]
            pw_hash = auth.hash_secret(pin)
            kdf_salt = crypto_store.new_kdf_salt()
            db.create_user(conn, username, pw_hash, kdf_salt)
            return {"ok": True}

        if cmd == "login":
            username = req["username"]
            pin = req["pin"]
            user = db.get_user(conn, username)
            if not user:
                return {"ok": False, "err": "user_not_found"}
            stored_hash, _salt = user
            if not auth.verify_secret(stored_hash, pin):
                return {"ok": False, "err": "bad_credentials"}
            token = _issue_token(username)
            return {"ok": True, "token": token}

        # Authenticated commands use token
        token = req.get("token", "")
        username = _get_username_from_token(token)
        if not username:
            return {"ok": False, "err": "unauthorized"}

        pin = req.get("pin", "")
        user = db.get_user(conn, username)
        if not user:
            return {"ok": False, "err": "user_not_found"}
        stored_hash, kdf_salt = user
        if not auth.verify_secret(stored_hash, pin):
            return {"ok": False, "err": "bad_credentials"}

        key = crypto_store.derive_key(pin, kdf_salt)
        aad = username.encode("utf-8")

        if cmd == "clockin":
            shift = {
                "username": username,
                "task": req["task"],
                "location": req["location"],
                "start": int(time.time()),
                "end": None,
                "notes": req.get("notes", ""),
            }
            nonce, ciphertext = crypto_store.encrypt_shift(shift, key, aad)
            shift_id = db.insert_shift_blob(conn, username, nonce, ciphertext)
            return {"ok": True, "shift_id": shift_id}

        if cmd == "clockout":
            last = db.get_last_shift_blob(conn, username)
            if not last:
                return {"ok": False, "err": "no_shifts"}
            shift_id, nonce, ciphertext, _ = last
            shift = crypto_store.decrypt_shift(nonce, ciphertext, key, aad)
            if shift.get("end") is not None:
                return {"ok": False, "err": "already_ended"}
            shift["end"] = int(time.time())
            if req.get("notes"):
                shift["notes"] = (shift.get("notes", "") + "\n" + req["notes"]).strip()
            new_nonce, new_ciphertext = crypto_store.encrypt_shift(shift, key, aad)
            db.update_shift_blob(conn, shift_id, new_nonce, new_ciphertext)
            return {"ok": True, "shift_id": shift_id}

        if cmd == "list":
            rows = db.list_shift_blobs(conn, username)
            shifts = []
            for shift_id, nonce, ciphertext, created_at in rows:
                try:
                    shift = crypto_store.decrypt_shift(nonce, ciphertext, key, aad)
                    shifts.append({"id": shift_id, "created_at": created_at, "shift": shift})
                except Exception:
                    shifts.append({"id": shift_id, "created_at": created_at, "shift": None, "err": "decrypt_failed"})
            return {"ok": True, "items": shifts}

        return {"ok": False, "err": "unknown_cmd"}
    finally:
        conn.close()

def serve(db_path: str) -> None:
    with socket.create_server((HOST, PORT)) as srv:
        print(f"[plain] listening on {HOST}:{PORT}, db={os.path.abspath(db_path)}")
        while True:
            conn, addr = srv.accept()
            with conn:
                try:
                    req = recv_msg(conn)
                    resp = handle_request(req, db_path)
                except Exception as e:
                    resp = {"ok": False, "err": f"server_error: {type(e).__name__}"}
                send_msg(conn, resp)

if __name__ == "__main__":
    serve("vault.db")