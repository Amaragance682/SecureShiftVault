import sqlite3

conn = sqlite3.connect("vault.db")
cur = conn.execute("SELECT username, pw_hash FROM users;")

for row in cur.fetchall():
    print(row)

conn.close()