import base64, hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def load_pubkey_hex(hex_str: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))

def verify_sig(pubkey: ed25519.Ed25519PublicKey, msg: bytes, sig_hex: str) -> bool:
    try:
        sig = bytes.fromhex(sig_hex)
        pubkey.verify(sig, msg)
        return True
    except Exception:
        return False

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def calc_merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    layer = leaves
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]

def verify_merkle_proof(leaf: bytes, proof: list[str], root_hex: str, index: int) -> bool:
    node = leaf; idx = index
    for sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        node = sha256(node+sib) if idx%2==0 else sha256(sib+node)
        idx //= 2
    return node.hex() == root_hex.lower()
