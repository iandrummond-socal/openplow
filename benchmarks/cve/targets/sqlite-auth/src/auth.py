"""Username/password login backed by a SQLite users table."""

import sqlite3


def login(db_path, username, password):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    query = "SELECT id FROM users WHERE name = '%s' AND password = '%s'" % (username, password)
    row = cur.execute(query).fetchone()
    con.close()
    return row is not None
