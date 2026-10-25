"""Username/password login backed by a SQLite users table."""

import hashlib
import hmac
import os
import sqlite3
from contextlib import closing

_SCRYPT = {"n": 2**14, "r": 8, "p": 1}
_DUMMY_SALT = b"\x00" * 16


def _hash(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


def init_db(db_path):
    with closing(sqlite3.connect(db_path)) as con, con:
        con.execute("CREATE TABLE IF NOT EXISTS users "
                    "(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, "
                    "salt BLOB NOT NULL, pw_hash BLOB NOT NULL)")


def add_user(db_path, username, password):
    salt = os.urandom(16)
    with closing(sqlite3.connect(db_path)) as con, con:
        con.execute("INSERT INTO users (name, salt, pw_hash) VALUES (?, ?, ?)",
                    (username, salt, _hash(password, salt)))


def login(db_path, username, password):
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    with closing(sqlite3.connect(db_path)) as con:
        row = con.execute("SELECT salt, pw_hash FROM users WHERE name = ?",
                          (username,)).fetchone()
    # Hash even for an unknown user so timing does not reveal which names exist.
    salt, expected = row if row else (_DUMMY_SALT, None)
    actual = _hash(password, salt)
    return expected is not None and hmac.compare_digest(actual, expected)
