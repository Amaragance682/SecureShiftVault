"""
db.py - SQLite persistence layer for SecureShiftVault

Responsibilities:
- Create/open the SQLite database
- Create schema (users + encrypted shift blobs)
- Store and retrieve user credential hashes + KDF salt
- Store and retrieve encrypted shift entries (nonce + ciphertext)
"""

from __future__ import annotations

import sqlite3
import time
from typing import Optional, List, Tuple


def connect(db_path: str) -> sqlite3.Connection:
    """Open a SQLite connection with sensible defaults."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables if they do not exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username   TEXT PRIMARY KEY,
            pw_hash    TEXT NOT NULL,
            kdf_salt   BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shifts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            nonce      BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        );
        """
    )
    conn.commit()


def create_user(conn: sqlite3.Connection, username: str, pw_hash: str, kdf_salt: bytes) -> None:
    """Insert a new user."""
    conn.execute(
        "INSERT INTO users(username, pw_hash, kdf_salt, created_at) VALUES(?,?,?,?)",
        (username, pw_hash, sqlite3.Binary(kdf_salt), int(time.time())),
    )
    conn.commit()


def get_user(conn: sqlite3.Connection, username: str) -> Optional[Tuple[str, bytes]]:
    """
    Return (pw_hash, kdf_salt) for user, or None if not found.
    """
    cur = conn.execute("SELECT pw_hash, kdf_salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return None
    pw_hash, kdf_salt = row
    return pw_hash, bytes(kdf_salt)


def insert_shift_blob(conn: sqlite3.Connection, username: str, nonce: bytes, ciphertext: bytes) -> int:
    """Insert an encrypted shift record and return its row id."""
    cur = conn.execute(
        "INSERT INTO shifts(username, nonce, ciphertext, created_at) VALUES(?,?,?,?)",
        (username, sqlite3.Binary(nonce), sqlite3.Binary(ciphertext), int(time.time())),
    )
    conn.commit()
    return int(cur.lastrowid)


def update_shift_blob(conn: sqlite3.Connection, shift_id: int, nonce: bytes, ciphertext: bytes) -> None:
    """Update an existing encrypted shift record."""
    conn.execute(
        "UPDATE shifts SET nonce=?, ciphertext=? WHERE id=?",
        (sqlite3.Binary(nonce), sqlite3.Binary(ciphertext), shift_id),
    )
    conn.commit()


def list_shift_blobs(conn: sqlite3.Connection, username: str) -> List[Tuple[int, bytes, bytes, int]]:
    """
    Return list of (id, nonce, ciphertext, created_at) for given user.
    """
    cur = conn.execute(
        "SELECT id, nonce, ciphertext, created_at FROM shifts WHERE username=? ORDER BY id ASC",
        (username,),
    )
    out: List[Tuple[int, bytes, bytes, int]] = []
    for shift_id, nonce, ciphertext, created_at in cur.fetchall():
        out.append((int(shift_id), bytes(nonce), bytes(ciphertext), int(created_at)))
    return out


def get_last_shift_blob(conn: sqlite3.Connection, username: str) -> Optional[Tuple[int, bytes, bytes, int]]:
    """
    Return most recent (id, nonce, ciphertext, created_at) or None.
    """
    cur = conn.execute(
        "SELECT id, nonce, ciphertext, created_at FROM shifts WHERE username=? ORDER BY id DESC LIMIT 1",
        (username,),
    )
    row = cur.fetchone()
    if not row:
        return None
    shift_id, nonce, ciphertext, created_at = row
    return int(shift_id), bytes(nonce), bytes(ciphertext), int(created_at)
