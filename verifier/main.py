# verifier/main.py

from flask import Flask, request, jsonify
import sqlite3, json, os, requests, datetime, logging
from datetime import timezone
from crypto_utils import (
    sha256,
    load_pubkey_hex,
    verify_sig,
    calc_merkle_root,
    verify_merkle_proof
)

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
    existing = {r[1] for r in cur.execute("PRAGMA table_info(logs)").fetchall()}
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


# --- Fetch & cache CRL con firma obbligatoria e Merkle‐root soft -------------
def fetch_crl():
    crl = None
    # 1) Provo a scaricare fresh
    try:
        r = requests.get(ISSUER_CRL_URL, timeout=3, verify=False)
        r.raise_for_status()
        crl = r.json()
    except Exception as e:
        app.logger.warning("CRL fetch failed (%s), uso cache se disponibile", e)
        if os.path.exists(CRL_CACHE_PATH):
            try:
                crl = json.load(open(CRL_CACHE_PATH))
                app.logger.debug("Uso CRL cache ts %s", crl.get("timestamp"))
            except Exception as e2:
                app.logger.error("Cache CRL invalida: %s", e2)
        if crl is None:
            return None

    # 2) Verifica obbligatoria della firma Ed25519
    payload = json.dumps(
        {
            "merkle_root": crl["merkle_root"],
            "timestamp":   crl["timestamp"],
            "version":     crl["version"],
        },
        sort_keys=True
    ).encode()
    sig_hex = crl.get("signature", "")
    if not verify_sig(ISSUER_PK, payload, sig_hex):
        app.logger.error("CRL signature INVALID – rigetto")
        raise Exception("Invalid CRL signature")
    app.logger.debug("CRL signature valid")

    # 3) Ricalcolo Merkle‐root: se mismatch, loggo ma proseguo
    try:
        leaves   = [sha256(cid.encode()) for cid in crl.get("revoked", [])]
        computed = calc_merkle_root(leaves).hex()
        if computed.lower() != crl["merkle_root"].lower():
            app.logger.warning(
                "CRL merkle_root mismatch: expected %s, got %s – proceeding anyway",
                crl["merkle_root"], computed
            )
        else:
            app.logger.debug("CRL merkle_root verified")
    except Exception as e:
        app.logger.warning("Errore ricalcolo Merkle-root: %s – proceeding anyway", e)

    # 4) Cache e ritorno
    try:
        os.makedirs(os.path.dirname(CRL_CACHE_PATH), exist_ok=True)
        with open(CRL_CACHE_PATH, "w") as f:
            json.dump(crl, f, separators=(",", ":"))
    except Exception as e:
        app.logger.error("Impossibile scrivere cache CRL: %s", e)

    return crl


# --- Verifica completa della presentation -------------------------------
def verify_presentation(pres):
    # 0) anti-replay: timestamp freshness
    ts_str = pres.get("timestamp", "")
    try:
        ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return False, "invalid_timestamp"
    now = datetime.datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    if abs((now - ts).total_seconds()) > PRES_FRESHNESS:
        return False, "stale_presentation"

    # 1) holder signature
    cred = pres.get("credential", {})
    holder_hex = cred.get("holder_pk")
    if not holder_hex:
        return False, "missing_holder_pk"
    holder_pk = load_pubkey_hex(holder_hex)
    sig_w = pres.get("sig_wallet", "")
    msg_w = json.dumps({k: v for k, v in pres.items() if k != "sig_wallet"},
                       sort_keys=True).encode()
    if not verify_sig(holder_pk, msg_w, sig_w):
        return False, "wallet_sig_invalid"

    # 2) issuer signature
    sig_i = cred.get("sig_issuer", "")
    signed = {k: v for k, v in cred.items() if k not in ("sig_issuer", "holder_pk")}
    msg_i = json.dumps(signed, sort_keys=True).encode()
    if not verify_sig(ISSUER_PK, msg_i, sig_i):
        return False, "issuer_sig_invalid"

    # 3) expiration
    exp = datetime.datetime.fromisoformat(
        cred.get("expiration_date", "").replace("Z", "+00:00")
    )
    if now > exp:
        return False, "credential_expired"

    # 4) fetch/cache CRL
    crl = fetch_crl()
    if crl is None:
        return False, "crl_unavailable"

    # 5) **Membership fallback**: se la credenziale è nella lista, è revocata
    cid = cred.get("credential_id")
    if cid in crl.get("revoked", []):
        return False, "credential_revoked"

    # 6) revoca tramite Merkle‐proof O(log n) per conferma
    proof_url = ISSUER_CRL_URL.replace("/crl", f"/proof/{cid}")
    try:
        rp = requests.get(proof_url, timeout=3, verify=False)
        rp.raise_for_status()
        proof = rp.json()
        proof_list = proof.get("path", [])
        index      = proof.get("leaf_index", 0)
        root_hex   = proof.get("root", crl["merkle_root"])
        leaf       = sha256(cid.encode())
        if verify_merkle_proof(leaf, proof_list, root_hex, index):
            # se la proof dice “membership in revoked tree”
            return False, "credential_revoked"
    except requests.HTTPError as e:
        app.logger.warning("Proof non disponibile per %s: %s", cid, e)
        return False, "proof_unavailable"
    except Exception as e:
        app.logger.error("Errore Merkle-proof per %s: %s", cid, e)
        return False, "revoked_or_tampered"

    # 7) commitment check
    for attr, bundle in pres.get("revealed", {}).items():
        salt = bytes.fromhex(bundle.get("salt", ""))
        val  = bundle.get("value", "").encode()
        if sha256(salt + val).hex() != bundle.get("comm", "").lower():
            return False, f"commitment_mismatch:{attr}"

    # 8) policy enforcement
    for needed in pres.get("need", []):
        if needed not in pres.get("revealed", {}):
            return False, "policy_unsatisfied"

    return True, "valid"


# --- Endpoint /verify ------------------------------------------------------
@app.route("/verify", methods=["POST"])
def verify():
    try:
        pres = request.get_json(force=True)

        # 1) replay persistente
        cid, _ = _extract_ids(pres)
        if cid:
            con = sqlite3.connect(DB_PATH); cur = con.cursor()
            cur.execute(
                "SELECT COUNT(1) FROM logs "
                "WHERE actor_to='verifier' AND credential_id=? AND verdict='valid'",
                (cid,)
            )
            if cur.fetchone()[0] > 0:
                resp = {"result": "invalid", "reason": "credential_replay"}
                log_interaction("wallet", "verifier", pres, resp,
                                "invalid", "credential_replay")
                return jsonify(resp), 400
            con.close()

        # 2) verifica completa
        ok, reason = verify_presentation(pres)
        resp = {"result": "valid" if ok else "invalid", "reason": reason}
        log_interaction("wallet", "verifier", pres, resp,
                        "valid" if ok else "invalid", reason)
        return jsonify(resp), (200 if ok else 400)

    except Exception as e:
        app.logger.exception("Error in /verify")
        return jsonify({"error": "internal_error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
