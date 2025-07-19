import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

out_sql = []
keys = {}

for i in range(1, 11):
    sid = f"stud{i:03d}"
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    # raw bytes → hex
    sk_hex = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    pk_hex = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    # prepara riga SQL
    out_sql.append(f"INSERT INTO students(student_id, pubkey_hex) VALUES('{sid}','{pk_hex}');")
    # salviamo le private key in un JSON per il wallet
    keys[sid] = sk_hex

# Salva file SQL
with open("data/populate_students.sql", "w") as f:
    f.write("\n".join(out_sql))

# Salva file chiavi per il wallet
with open("../wallet/data/student_keys.json", "w") as f:
    json.dump(keys, f, indent=2)

print("Generated data/populate_students.sql and data/student_keys.json")