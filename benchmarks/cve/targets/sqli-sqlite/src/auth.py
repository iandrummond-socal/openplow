"""Login check — minimal reproduction of SQL injection (CWE-89).

Representative of countless real CVEs: user input is concatenated straight into
the SQL text, so a crafted password turns the WHERE clause always-true and
bypasses authentication.
"""

import sqlite3


def login(db_path, username, password):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    # VULN (CWE-89): username/password interpolated into the query string.
    query = "SELECT id FROM users WHERE name = '%s' AND password = '%s'" % (username, password)
    row = cur.execute(query).fetchone()
    con.close()
    return row is not None
