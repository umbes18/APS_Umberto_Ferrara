"""
Modulo CRL con Merkle tree – Issuer side
"""

import json, os, datetime, hashlib, threading, time, tempfile
from cryptography.hazmat.primitives.asymmetric import ed25519

CRL_PATH   = "/app/data/crl.json"
ROLL_TIME  = 60                      # flush periodico (s)


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _merkle_root(leaves: list[str]) -> str:
    if not leaves:
        # SHA256("") canonicalizzato per albero vuoto
        return hashlib.sha256(b"").hexdigest()

    layer = [_sha(cid.encode()) for cid in sorted(leaves)]
    while len(layer) > 1:
        if len(layer) % 2:                     # duplica se dispari
            layer.append(layer[-1])
        layer = [_sha(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0].hex()


class CRLUpdater:
    """
    Gestisce in RAM e su disco la CRL firmata dall’Issuer.
    """

    def __init__(self, issuer_sk: ed25519.Ed25519PrivateKey):
        self._issuer_sk = issuer_sk

        # carica da disco o crea struttura vuota
        if os.path.exists(CRL_PATH):
            with open(CRL_PATH) as f:
                self.crl = json.load(f)
        else:
            self.crl = {
                "version": 0,
                "timestamp": "",
                "revoked": [],
                "merkle_root": "",
                "signature": "",
            }

        os.makedirs(os.path.dirname(CRL_PATH), exist_ok=True)

        # calcola radice + firma subito
        self._recompute()
        self._flush()

        # thread di roll-over periodico
        threading.Thread(target=self._auto_flush, daemon=True).start()

    # ------------------------------------------------------------------
    # API pubblico
    # ------------------------------------------------------------------
    def revoke(self, credential_id: str) -> bool:
        """
        Aggiunge l'ID nella lista 'revoked'.
        Ritorna True se era nuovo, False se già presente.
        """
        if credential_id in self.crl["revoked"]:
            return False
        self.crl["revoked"].append(credential_id)
        self._recompute()
        self._flush()
        return True

    # ------------------------------------------------------------------
    # Funzioni interne
    # ------------------------------------------------------------------
    def _recompute(self):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        # aggiorna meta-dati
        self.crl["version"] += 1
        self.crl["timestamp"] = now
        self.crl["merkle_root"] = _merkle_root(self.crl["revoked"])

        # firma sulla tupla (root, version, timestamp) ordinata
        sign_payload = json.dumps(
            {
                "merkle_root": self.crl["merkle_root"],
                "version": self.crl["version"],
                "timestamp": self.crl["timestamp"],
            },
            sort_keys=True,
        ).encode()

        self.crl["signature"] = self._issuer_sk.sign(sign_payload).hex()

    def _flush(self):
        # tmp unico e atomico nella stessa dir di crl.json
        fd, tmp_path = tempfile.mkstemp(
            dir=os.path.dirname(CRL_PATH), prefix="crl_", suffix=".tmp"
        )
        with os.fdopen(fd, "w") as f:
            json.dump(self.crl, f, separators=(",", ":"))

        # tenta la sostituzione; se un altro worker ha già finito,
        # il nostro tmp non serve più -> lo rimuoviamo
        try:
            os.replace(tmp_path, CRL_PATH)
        except FileNotFoundError:
            os.remove(tmp_path)

    def _auto_flush(self):
        while True:
            time.sleep(ROLL_TIME)
            self._flush()
