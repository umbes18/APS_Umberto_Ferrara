# crl_updater.py
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
    def __init__(self, issuer_sk: ed25519.Ed25519PrivateKey):
        self._issuer_sk = issuer_sk
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

        # ✅ firma subito anche se lista vuota / file vecchio
        if not self.crl.get("timestamp") or not self.crl.get("signature"):
            self._recompute()

        self._flush()
        threading.Thread(target=self._auto_flush, daemon=True).start()

    def revoke(self, credential_id: str) -> bool:
        if credential_id in self.crl["revoked"]:
            return False
        self.crl["revoked"].append(credential_id)
        self._recompute()
        self._flush()
        return True

    def _recompute(self):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.crl["timestamp"] = now
        self.crl["version"] += 1
        self.crl["merkle_root"] = _merkle_root(self.crl["revoked"])
        payload = json.dumps(
            { "merkle_root": self.crl["merkle_root"],
              "timestamp":   self.crl["timestamp"],
              "version":     self.crl["version"] },
            sort_keys=True, separators=(",",":")
        ).encode()
        self.crl["signature"] = self._issuer_sk.sign(payload).hex()

    def _flush(self):
        dirn = os.path.dirname(CRL_PATH)
        os.makedirs(dirn, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=dirn)
        with os.fdopen(fd, "w") as f:
            json.dump(self.crl, f, separators=(",", ":"))
        os.replace(tmp_path, CRL_PATH)

    def _auto_flush(self):
        while True:
            time.sleep(ROLL_TIME)
            # aggiorna timestamp/firma periodicamente
            self._recompute()
            self._flush()
