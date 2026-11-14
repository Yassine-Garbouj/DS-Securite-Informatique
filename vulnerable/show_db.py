import sqlite3

con = sqlite3.connect("data/app.db")

print("=== COMPTES ===")
for row in con.execute("SELECT id, username, email, password_hash FROM users"):
    print(row)

print("\n=== FICHIERS ===")
for row in con.execute("SELECT id, owner_id, original_name, sha256 FROM files"):
    print(row)

print("\n=== PARTAGES ===")
for row in con.execute("SELECT * FROM shares"):
    print(row)

print("\n=== JOURNAL ===")
for row in con.execute("SELECT ts, username, action, result FROM audit_log"):
    print(row)

con.close()