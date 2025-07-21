from flask import Flask, request, jsonify
import sqlite3, json, os, requests, datetime, hashlib, logging
from datetime import timezone
from crypto_utils import sha256, load_pubkey_hex, verify_sig

app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.DEBUG)

# Configurazione
DB_PATH         = "/app/data/verifier_logs.db"
CRL_CACHE_PATH  = "/app/data/crl_cache.json"
ISSUER_CRL_URL  = os.getenv("ISSUER_CRL_URL", "https://issuer:8000/crl")
ISSUER_PK_HEX   = os.getenv("ISSUER_PK_HEX", "")
ISSUER_PK       = load_pubkey_hex(ISSUER_PK_HEX)

PRES_FRESHNESS  = 3000    # secondi


# --- Schema e helper per il logging --------------------------------------
def ensure_logs_schema():
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
        )
    """)
    cur.execute("PRAGMA table_info(logs)")
    existing = {r[1] for r in cur.fetchall()}
    for col in ("credential_id","student_id","actor_from","actor_to",
                "request","response","verdict","reason","created_at"):
        if col not in existing:
            cur.execute(f"ALTER TABLE logs ADD COLUMN {col} TEXT")
            app.logger.info("Added column %s to logs table", col)
    con.commit(); con.close()

def _extract_ids(req_obj):
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
        ) VALUES(?,?,?,?,?,?,?,?,?)
    """, (
        cid, sid,
        frm, to,
        json.dumps(req_obj, sort_keys=True),
        json.dumps(resp_obj, sort_keys=True),
        verdict, reason,
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    ))
    con.commit(); con.close()

ensure_logs_schema()


# --- Fetch & cache CRL ----------------------------------------------------
def fetch_crl():
    try:
        r = requests.get(ISSUER_CRL_URL, timeout=3, verify=False)
        r.raise_for_status()
        crl = r.json()
        # Verifica signature (logga ma non blocca)
        payload = f"{crl['merkle_root']}|{crl['version']}|{crl['timestamp']}".encode()
        try:
            valid = verify_sig(ISSUER_PK, payload, crl.get("signature",""))
            app.logger.debug("CRL sig valid: %s", valid)
        except Exception as e:
            app.logger.warning("CRL sig check error: %s", e)
        # Salva in cache
        with open(CRL_CACHE_PATH, "w") as f:
            json.dump(crl, f, separators=(",",":"))
        return crl
    except Exception as e:
        app.logger.warning("CRL fetch failed (%s), using cache", e)
        if os.path.exists(CRL_CACHE_PATH):
            try:
                cached = json.load(open(CRL_CACHE_PATH))
                app.logger.debug("Using CRL cache ts %s", cached.get("timestamp"))
                return cached
            except Exception as e2:
                app.logger.error("Invalid CRL cache: %s", e2)
        return None


# --- Verifica completa della presentazione -------------------------------
def verify_presentation(pres):
    # 0) anti-replay: timestamp freshness
    ts_str = pres.get("timestamp","")
    try:
        ts = datetime.datetime.fromisoformat(ts_str.replace("Z","+00:00"))
    except Exception:
        return False, "invalid_timestamp"
    now = datetime.datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    if abs((now - ts).total_seconds()) > PRES_FRESHNESS:
        return False, "stale_presentation"

    # 1) firma Wallet
    cred = pres.get("credential", {})
    holder_hex = cred.get("holder_pk")
    if not holder_hex:
        return False, "missing_holder_pk"
    holder_pk = load_pubkey_hex(holder_hex)
    sig_w = pres.get("sig_wallet","")
    msg_w = json.dumps({k:v for k,v in pres.items() if k!="sig_wallet"}, sort_keys=True).encode()
    if not verify_sig(holder_pk, msg_w, sig_w):
        return False, "wallet_sig_invalid"

    # 2) firma Issuer
    sig_i = cred.get("sig_issuer","")
    signed = {k:v for k,v in cred.items() if k not in ("sig_issuer","holder_pk")}
    msg_i = json.dumps(signed, sort_keys=True).encode()
    if not verify_sig(ISSUER_PK, msg_i, sig_i):
        return False, "issuer_sig_invalid"

    # 3) controllo scadenza
    exp = datetime.datetime.fromisoformat(cred.get("expiration_date","").replace("Z","+00:00"))
    if now > exp:
        return False, "credential_expired"

    # 4) fetch/cache CRL
    crl = fetch_crl()
    if crl is None:
        return False, "crl_unavailable"

    # 5) membership revoca
    cid = cred.get("credential_id")
    if cid in crl.get("revoked", []):
        return False, "credential_revoked"

    # 6) commitment check
    for attr,bundle in pres.get("revealed", {}).items():
        salt = bytes.fromhex(bundle.get("salt",""))
        val  = bundle.get("value","").encode()
        if sha256(salt + val).hex() != bundle.get("comm","").lower():
            return False, f"commitment_mismatch:{attr}"

    # 7) policy enforcement
    for needed in pres.get("need", []):
        if needed not in pres.get("revealed", {}):
            return False, "policy_unsatisfied"

    return True, "valid"


# --- Endpoint /verify ------------------------------------------------------
@app.route("/verify", methods=["POST"])
def verify():
    try:
        pres = request.get_json(force=True)
        # 1) controllo replay persistente
        cid, _ = _extract_ids(pres)
        if cid:
            con = sqlite3.connect(DB_PATH); cur = con.cursor()
            cur.execute(
                "SELECT COUNT(1) FROM logs WHERE actor_to='verifier' AND credential_id=? AND verdict='valid'",
                (cid,)
            )
            if cur.fetchone()[0] > 0:
                resp = {"result":"invalid","reason":"credential_replay"}
                log_interaction("wallet","verifier", pres, resp, "invalid", "credential_replay")
                return jsonify(resp), 400
            con.close()

        # 2) normale verifica
        ok, reason = verify_presentation(pres)
        resp = {"result": "valid" if ok else "invalid", "reason": reason}
        log_interaction("wallet","verifier", pres, resp, "valid" if ok else "invalid", reason)
        return jsonify(resp), (200 if ok else 400)
    except Exception as e:
        app.logger.exception("Error in /verify")
        return jsonify({"error":"internal_error","message":str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
