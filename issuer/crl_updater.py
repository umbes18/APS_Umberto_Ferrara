import json, os, datetime, hashlib, threading, time, tempfile
from cryptography.hazmat.primitives.asymmetric import ed25519

CRL_PATH   = "/app/data/crl.json"
ROLL_TIME  = 60  # flush periodico (s)

def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def _merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return _sha(b"").hex()
    level = [ _sha(x.encode()) for x in leaves ]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            left, right = level[i], level[i+1]
            next_level.append(_sha(left + right))
        level = next_level
    return level[0].hex()

class CRLUpdater:
    """
    Gestisce in RAM e su disco la CRL firmata dall’Issuer.
    """
    def __init__(self, issuer_sk: ed25519.Ed25519PrivateKey):
        self._issuer_sk = issuer_sk

        # carica da disco o struttura vuota
        if os.path.exists(CRL_PATH):
            with open(CRL_PATH, "r") as f:
                self.crl = json.load(f)
        else:
            self.crl = {
                "version":     0,
                "timestamp":   "",
                "revoked":     [],
                "merkle_root": "",
                "signature":   ""
            }

        # Inizializza subito la CRL sul filesystem
        self._flush()

        # avvia il flush periodico in background
        threading.Thread(target=self._auto_flush, daemon=True).start()

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
        # 1) Aggiorniamo il timestamp **PRIMA** di firmare
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.crl["timestamp"] = now

        # 2) Incrementiamo la versione
        self.crl["version"] += 1

        # 3) Ricaviamo il nuovo Merkle root
        self.crl["merkle_root"] = _merkle_root(self.crl["revoked"])

        # 4) Firmiamo la tupla (root, version, timestamp)
        payload = json.dumps(
            {
                "merkle_root": self.crl["merkle_root"],
                "timestamp":   self.crl["timestamp"],
                "version":     self.crl["version"],
            },
            sort_keys=True
        ).encode()
        self.crl["signature"] = self._issuer_sk.sign(payload).hex()

    def _flush(self):
        # Scrive atomicamente self.crl in CRL_PATH
        dirn = os.path.dirname(CRL_PATH)
        os.makedirs(dirn, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=dirn)
        with os.fdopen(fd, "w") as f:
            json.dump(self.crl, f, separators=(",", ":"))
        try:
            os.replace(tmp_path, CRL_PATH)
        except FileNotFoundError:
            os.remove(tmp_path)

    def _auto_flush(self):
        while True:
            time.sleep(ROLL_TIME)
            self._flush()
