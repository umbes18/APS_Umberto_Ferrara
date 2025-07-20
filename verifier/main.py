from flask import Flask, request, jsonify, render_template
import sqlite3, json, datetime, threading, time, os, requests, hashlib, logging
from cryptography.hazmat.primitives.asymmetric import ed25519

app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.DEBUG)

# ---------- config -----------------------------------------------------------
DB_PATH        = "/app/data/verifier_logs.db"
CRL_CACHE_PATH = "/app/data/crl_cache.json"
ISSUER_CRL_URL = os.getenv("ISSUER_CRL_URL", "https://issuer:8000/crl")
ISSUER_PK_HEX  = os.getenv("ISSUER_PK_HEX")
ISSUER_PK      = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ISSUER_PK_HEX))
PULL_INTERVAL  = 600  # sec

# ---------- schema & logging -------------------------------------------------
def ensure_logs_schema():
    """
    Crea la tabella logs oppure ne migra lo schema aggiungendo
    credential_id/student_id + nuove colonne se mancanti.
    """
    con = sqlite3.connect(DB_PATH); cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id TEXT,
            student_id    TEXT,
            actor_from    TEXT,
            actor_to      TEXT,
            request       TEXT,
            response      TEXT,
            verdict       TEXT,
            reason        TEXT,
            created_at    TEXT
        )""")

    # migrazione: aggiungi colonne assenti
    cur.execute("PRAGMA table_info(logs)")
    existing = {row[1] for row in cur.fetchall()}
    for col in ("credential_id", "student_id",
                "actor_from", "actor_to",
                "request", "response",
                "verdict", "reason", "created_at"):
        if col not in existing:
            cur.execute(f"ALTER TABLE logs ADD COLUMN {col} TEXT")
            app.logger.info("Added column %s to logs table", col)

    con.commit(); con.close()

ensure_logs_schema()

def _extract_ids(req_obj: dict) -> tuple[str|None, str|None]:
    """Prova a estrarre credential_id e student_id dalla request."""
    if not isinstance(req_obj, dict):
        return None, None
    # presentation: {"credential": {...}}
    cred = req_obj.get("credential")
    if cred and isinstance(cred, dict):
        return cred.get("credential_id"), cred.get("subject")
    # request di presentazione: {"credential_id": ..}
    return req_obj.get("credential_id"), req_obj.get("student_id")

def log_interaction(frm, to, req_obj, resp_obj, verdict, reason):
    cid, sid = _extract_ids(req_obj)
    con = sqlite3.connect(DB_PATH); cur = con.cursor()
    cur.execute("""INSERT INTO logs(credential_id,student_id,
                                    actor_from,actor_to,
                                    request,response,
                                    verdict,reason,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
        (cid, sid,
         frm, to,
         json.dumps(req_obj,  sort_keys=True),
         json.dumps(resp_obj, sort_keys=True),
         verdict, reason,
         datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")))
    con.commit(); con.close()

# ---------- CRL handling -----------------------------------------------------
CRL = {"revoked": set(), "version": -1}

def verify_crl_signature(crl_obj: dict) -> bool:
    sig = bytes.fromhex(crl_obj.get("signature", ""))
    root_data = json.dumps(
        {k: crl_obj[k] for k in ("merkle_root", "version", "timestamp")},
        sort_keys=True).encode()
    try:
        ISSUER_PK.verify(sig, root_data)
        return True
    except Exception:
        return False

def download_crl_loop():
    global CRL
    while True:
        try:
            resp = requests.get(ISSUER_CRL_URL, timeout=5, verify=False)
            if resp.ok:
                crl_obj = resp.json()
                if crl_obj["version"] > CRL["version"] and verify_crl_signature(crl_obj):
                    CRL = {"revoked": set(crl_obj.get("revoked", [])),
                           "version": crl_obj["version"]}
                    with open(CRL_CACHE_PATH, "w") as f:
                        json.dump(crl_obj, f)
                    app.logger.info("CRL aggiornata (v%s)", crl_obj["version"])
        except Exception as e:
            app.logger.warning("CRL sync failed: %s", e)
        time.sleep(PULL_INTERVAL)

if os.path.exists(CRL_CACHE_PATH):
    with open(CRL_CACHE_PATH) as f:
        cached = json.load(f)
        if verify_crl_signature(cached):
            CRL = {"revoked": set(cached.get("revoked", [])),
                   "version": cached["version"]}

threading.Thread(target=download_crl_loop, daemon=True).start()

# ---------- verifica credenziale --------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def verify_presentation(pres: dict) -> tuple[bool, str]:
    cred = pres.get("credential")
    if not cred: return False, "missing_credential"

    # 1) firma Wallet
    holder_pk = cred.get("holder_pk")
    if not holder_pk: return False, "missing_holder_pk"
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(holder_pk))\
            .verify(bytes.fromhex(pres["sig_wallet"]),
                    json.dumps({k:v for k,v in pres.items() if k!="sig_wallet"},
                               sort_keys=True).encode())
    except Exception:
        return False, "wallet_sig_invalid"

    # 2) firma Issuer
    try:
        sig_issuer = bytes.fromhex(cred["sig_issuer"])
        signed = {k:v for k,v in cred.items() if k not in ("sig_issuer","holder_pk")}
        ISSUER_PK.verify(sig_issuer, json.dumps(signed, sort_keys=True).encode())
    except Exception:
        return False, "issuer_sig_invalid"

    # 3) validità temporale
    if datetime.datetime.strptime(cred["expiration_date"], "%Y-%m-%dT%H:%M:%SZ") < datetime.datetime.utcnow():
        return False, "credential_expired"

    # 4) revoca
    if cred["credential_id"] in CRL["revoked"]:
        return False, "credential_revoked"

    # 5) commitment check
    for attr, bundle in pres.get("revealed", {}).items():
        salt = bytes.fromhex(bundle["salt"])
        comm = bytes.fromhex(bundle["comm"])
        if sha256(salt + str(bundle["value"]).encode()) != comm:
            return False, f"commitment_mismatch:{attr}"

    # 6) policy
    need = pres.get("need", [])
    if any(n not in pres.get("revealed", {}) for n in need):
        return False, "policy_unsatisfied"

    return True, "valid"

# ---------- API --------------------------------------------------------------
@app.post("/verify")
def verify():
    pres = request.get_json(force=True)
    ok, reason = verify_presentation(pres)
    resp = {"result": "valid" if ok else "invalid", "reason": reason}
    log_interaction("wallet", "verifier", pres, resp,
                    resp["result"], reason)
    return jsonify(resp), (200 if ok else 400)

@app.get("/healthz")
def health():
    return {"status": "ok",
            "time": datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z"}

# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
