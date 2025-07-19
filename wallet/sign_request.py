import json
from cryptography.hazmat.primitives.asymmetric import ed25519

# Carica la private key di stud001 dal JSON generato da gen_student_keys.py
with open("data/student_keys.json") as f:
    keys = json.load(f)
sk_hex = keys["stud001"]
sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk_hex))

# Parametri esatti della richiesta
student_id = "stud001"
exam_name  = "Sicurezza dei Sistemi"
exam_date  = "2025-06-20"
nonce      = "e1821f4a-7dec-11d0-a765-00a0c91e6bf6"
ts         = "2025-07-18T18:00:00Z"

# Messaggio e firma
msg = f"{student_id}|{exam_name}|{exam_date}|{nonce}|{ts}".encode()
sig = sk.sign(msg).hex()
print(sig)