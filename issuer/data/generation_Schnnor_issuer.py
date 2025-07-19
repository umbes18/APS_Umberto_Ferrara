from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# 1. Genera la chiave privata Ed25519
issuer_sk = ed25519.Ed25519PrivateKey.generate()

# 2. Estrai i 32 byte raw (PrivateKey.raw_bytes)
priv_bytes = issuer_sk.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

# 3. Stampa in hex per copiarla nel codice
print(priv_bytes.hex())