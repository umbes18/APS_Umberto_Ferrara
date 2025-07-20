#!/usr/bin/env python3
"""
Popola `data/academic_records.db` con 10 studenti (stud001-stud010)
e genera le rispettive chiavi Ed25519:

    - chiave privata  → wallet_keys/studXXX.key
    - chiave pubblica → tabella students (campo pubkey_hex)
"""
import os, pathlib, sqlite3
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

DB_PATH   = "data/academic_records.db"
KEYS_DIR  = pathlib.Path("wallet_keys")
NUM_STUD  = 10                       # quanti studenti creare

# 1) ricrea la tabella students
conn = sqlite3.connect(DB_PATH)
cur  = conn.cursor()
cur.execute("DROP TABLE IF EXISTS students")
cur.execute("""
    CREATE TABLE students(
      student_id TEXT PRIMARY KEY,
      pubkey_hex TEXT NOT NULL
    )
""")

# 2) genera chiavi & inserisce record
KEYS_DIR.mkdir(exist_ok=True, parents=True)

for i in range(1, NUM_STUD + 1):
    sid = f"stud{i:03d}"

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption()
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

    # salva la chiave privata (wallet_keys/studXXX.key)
    with open(KEYS_DIR / f"{sid}.key", "wb") as f:
        f.write(priv_bytes)

    # inserisce la chiave pubblica nel DB
    cur.execute(
        "INSERT INTO students(student_id, pubkey_hex) VALUES(?,?)",
        (sid, pub_bytes.hex())
    )

conn.commit()
conn.close()
print(f"✅ Creati {NUM_STUD} studenti e chiavi in {KEYS_DIR}/")
