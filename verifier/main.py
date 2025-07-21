from flask import Flask, request, jsonify, render_template
import sqlite3, json, datetime, threading, time, os, requests, hashlib, logging
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes

app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.DEBUG)

DB_PATH        = "/app/data/verifier_logs.db"
CRL_CACHE_PATH = "/app/data/crl_cache.json"
ISSUER_CRL_URL = os.getenv("ISSUER_CRL_URL", "https://issuer:8000/crl")
ISSUER_PK_HEX  = os.getenv("ISSUER_PK_HEX", "")
ISSUER_PK      = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ISSUER_PK_HEX))

# --------- schema & logging ------------------------------------------------
def ensure_logs_schema():
    con = sqlite3.connect(DB_PATH); cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id TEXT,
            student_id TEXT,
            actor_from TEXT,
            actor_to TEXT,
            request TEXT,
            response TEXT,
            verdict TEXT,
            reason TEXT,
            created_at TEXT
        )""")
    cur.execute("PRAGMA table_info(logs)")
    existing = {r[1] for r in cur.fetchall()}
    for col in ("credential_id","student_id","actor_from","actor_to",
                "request","response","verdict","reason","created_at"):
        if col not in existing:
            cur.execute(f"ALTER TABLE logs ADD COLUMN {col} TEXT")
            app.logger.info("Added column %s to logs table", col)
    con.commit(); con.close()


def _extract_ids(req_obj: dict):
    if not isinstance(req_obj, dict):
        return None, None
    cred = req_obj.get("credential")
    if isinstance(cred, dict):
        return cred.get("credential_id"), cred.get("subject")
    return req_obj.get("credential_id"), req_obj.get("student_id")


def log_interaction(frm, to, req_obj, resp_obj, verdict=None, reason=None):
    cid, sid = _extract_ids(req_obj)
    con = sqlite3.connect(DB_PATH); cur = con.cursor()
    cur.execute("""
        INSERT INTO logs(
          credential_id, student_id,
          actor_from, actor_to,
          request, response,
          verdict, reason, created_at
        ) VALUES(?,?,?,?,?,?,?,?,?)""", (
        cid, sid,
        frm, to,
        json.dumps(req_obj, sort_keys=True),
        json.dumps(resp_obj, sort_keys=True),
        verdict, reason,
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    ))
    con.commit(); con.close()

ensure_logs_schema()

# --------- helper di verifica ------------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def verify_presentation(pres: dict) -> tuple[bool, str]:
    # fetch immediato della CRL
    try:
        r = requests.get(ISSUER_CRL_URL, timeout=3, verify=False)
        if r.ok:
            crl_obj = r.json()
            # log versione e revocati
            app.logger.debug("Fetched CRL version %s, entries %s",
                              crl_obj.get("version"), crl_obj.get("revoked"))
            revoked = set(crl_obj.get("revoked", []))
        else:
            revoked = set()
    except Exception as e:
        app.logger.warning("CRL fetch error: %s", e)
        revoked = set()

    cred = pres.get("credential")
    if not cred:
        return False, "missing_credential"

    # 1) firma Wallet
    holder_pk = cred.get("holder_pk")
    if not holder_pk:
        return False, "missing_holder_pk"
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(holder_pk)) \
            .verify(bytes.fromhex(pres.get("sig_wallet","")),
                    json.dumps({k:v for k,v in pres.items() if k!="sig_wallet"},
                                sort_keys=True).encode())
    except Exception:
        return False, "wallet_sig_invalid"

    # 2) firma Issuer cred
    try:
        sig = bytes.fromhex(cred.get("sig_issuer",""))
        signed = {k:v for k,v in cred.items() if k not in ("sig_issuer","holder_pk")}
        ISSUER_PK.verify(sig, json.dumps(signed, sort_keys=True).encode())
    except Exception:
        return False, "issuer_sig_invalid"

    # 3) temporalità
    exp = datetime.datetime.strptime(cred.get("expiration_date",""), "%Y-%m-%dT%H:%M:%SZ")
    if exp < datetime.datetime.utcnow():
        return False, "credential_expired"

    # 4) revoca usando il set appena scaricato
    cid = cred.get("credential_id")
    app.logger.debug("Checking if %s in revoked set", cid)
    if cid in revoked:
        return False, "credential_revoked"

    # 5) commitment check
    for attr, bundle in pres.get("revealed", {}).items():
        if sha256(bytes.fromhex(bundle.get("salt","")) + bundle.get("value","").encode()) != bytes.fromhex(bundle.get("comm","")):
            return False, f"commitment_mismatch:{attr}"

    # 6) policy
    if any(n not in pres.get("revealed", {}) for n in pres.get("need", [])):
        return False, "policy_unsatisfied"

    return True, "valid"

# --------- endpoint /verify ------------------------------------------------
@app.route("/verify", methods=["POST"])
def verify():
    try:
        pres = request.get_json(force=True)
        ok, reason = verify_presentation(pres)
        resp = {"result": "valid" if ok else "invalid", "reason": reason}
        log_interaction("wallet", "verifier", pres, resp, "valid" if ok else "invalid", reason)
        return jsonify(resp), (200 if ok else 400)
    except Exception as e:
        app.logger.exception("Error in /verify")
        return jsonify({"error":"internal_error","message":str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
