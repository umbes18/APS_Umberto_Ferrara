# verifier/main.py
from flask import Flask, request, jsonify
import sqlite3, json, os, requests, datetime, hashlib, logging, secrets
from datetime import timezone
from typing import Optional, Tuple, List
from crypto_utils import sha256, load_pubkey_hex, verify_sig

app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.DEBUG)

# ── Config ──────────────────────────────────────────────────────────────────
DB_PATH         = "/app/data/verifier_logs.db"
CRL_CACHE_PATH  = "/app/data/crl_cache.json"
ISSUER_CRL_URL  = os.getenv("ISSUER_CRL_URL", "https://issuer:8000/crl")

ISSUER_PK_HEX   = os.getenv("ISSUER_PK_HEX", "")
ISSUER_PK       = load_pubkey_hex(ISSUER_PK_HEX)

VERIFIER_AUDIENCE = os.getenv("VERIFIER_AUDIENCE", "exam-portal")
CHALLENGE_TTL     = int(os.getenv("CHALLENGE_TTL", "300"))    # sec
PRES_FRESHNESS    = int(os.getenv("PRES_FRESHNESS", "3000"))  # sec

# CRL enforcement (nuovo)
ENFORCE_CRL_SIG   = os.getenv("ENFORCE_CRL_SIG", "1") == "1"
CRL_MAX_AGE       = int(os.getenv("CRL_MAX_AGE", "900"))      # sec
CRL_MAX_FUTURE    = int(os.getenv("CRL_MAX_FUTURE", "60"))    # sec

# ── DB schema & helpers ─────────────────────────────────────────────────────
def ensure_schema():
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS challenges(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id   TEXT UNIQUE,
            challenge    TEXT UNIQUE,
            audience     TEXT,
            need_json    TEXT,
            expires_at   TEXT,
            used_at      TEXT
        )
    """)
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

ensure_schema()

# ── Time helpers ────────────────────────────────────────────────────────────
def _now_utc(): return datetime.datetime.now(timezone.utc)
def _iso(dt: datetime.datetime) -> str:
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ── CRL helpers (firma & freschezza) ────────────────────────────────────────
def _verify_crl_sig(crl: dict) -> bool:
    # formato canonico (nuovo)
    try:
        payload = json.dumps(
            {"merkle_root": crl["merkle_root"], "timestamp": crl["timestamp"], "version": crl["version"]},
            sort_keys=True, separators=(",", ":")
        ).encode()
        if verify_sig(ISSUER_PK, payload, crl.get("signature", "")):
            return True
    except Exception:
        pass
    # formato legacy "root|version|timestamp" (compatibilità)
    try:
        legacy = f"{crl['merkle_root']}|{crl['version']}|{crl['timestamp']}".encode()
        if verify_sig(ISSUER_PK, legacy, crl.get("signature", "")):
            return True
    except Exception:
        pass
    return False

def _is_crl_fresh(crl: dict) -> Tuple[bool, str]:
    try:
        ts = datetime.datetime.fromisoformat(crl["timestamp"].replace("Z","+00:00"))
        now = _now_utc()
        if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
        age = (now - ts).total_seconds()
        skew = (ts - now).total_seconds()
        if age > CRL_MAX_AGE:
            return False, "crl_stale"
        if skew > CRL_MAX_FUTURE:
            return False, "crl_in_future"
        return True, "ok"
    except Exception:
        return False, "crl_bad_timestamp"

def _load_cached_crl() -> Optional[dict]:
    if os.path.exists(CRL_CACHE_PATH):
        try:
            return json.load(open(CRL_CACHE_PATH))
        except Exception:
            return None
    return None

def fetch_crl():
    # prova rete
    try:
        r = requests.get(ISSUER_CRL_URL, timeout=4, verify=False)
        r.raise_for_status()
        crl = r.json()
        if ENFORCE_CRL_SIG and not _verify_crl_sig(crl):
            app.logger.warning("CRL signature invalid (network)")
            raise ValueError("crl_bad_signature")
        ok, why = _is_crl_fresh(crl)
        if not ok:
            app.logger.warning("CRL freshness check failed (network): %s", why)
            raise ValueError(why)
        # save cache
        with open(CRL_CACHE_PATH, "w") as f:
            json.dump(crl, f, separators=(",",":"))
        return crl
    except Exception as e:
        app.logger.warning("CRL fetch failed (%s), trying cache", e)
        crl = _load_cached_crl()
        if crl is None:
            return None
        if ENFORCE_CRL_SIG and not _verify_crl_sig(crl):
            app.logger.error("Cached CRL signature invalid")
            return None
        ok, why = _is_crl_fresh(crl)
        if not ok:
            app.logger.error("Cached CRL not fresh: %s", why)
            return None
        return crl

# ── Challenge issuer ────────────────────────────────────────────────────────
@app.route("/challenge", methods=["POST"])
def challenge():
    body = request.get_json(force=True) if request.data else {}
    need = body.get("need") if isinstance(body, dict) else None
    if not isinstance(need, list) or not need:
        need = ["exam_name", "exam_date", "grade"]
    ch  = secrets.token_hex(16)
    rid = secrets.token_hex(16)
    aud = VERIFIER_AUDIENCE
    exp = _iso(_now_utc() + datetime.timedelta(seconds=CHALLENGE_TTL))
    con = sqlite3.connect(DB_PATH); cur = con.cursor()
    cur.execute("""INSERT INTO challenges(request_id, challenge, audience, need_json, expires_at)
                   VALUES (?,?,?,?,?)""", (rid, ch, aud, json.dumps(need, separators=(",",":")), exp))
    con.commit(); con.close()
    resp = {"request_id": rid, "need": need, "challenge": ch, "audience": aud, "expires_at": exp}
    return jsonify(resp), 200

# ── Merkle verification ─────────────────────────────────────────────────────
def _merkle_root_from_path(leaf_hash: bytes, leaf_index: int, path: List[str]) -> str:
    h = leaf_hash
    idx = leaf_index
    for sib_hex in path:
        sib = bytes.fromhex(sib_hex)
        if idx % 2 == 0:
            h = sha256(h + sib)
        else:
            h = sha256(sib + h)
        idx //= 2
    return h.hex()

# ── Presentation verification ───────────────────────────────────────────────
def verify_presentation(pres):
    now = _now_utc()

    # freshness sul timestamp firmato dal wallet
    ts_str = pres.get("timestamp","")
    try:
        ts = datetime.datetime.fromisoformat(ts_str.replace("Z","+00:00"))
    except Exception:
        return False, "invalid_timestamp"
    if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
    if abs((now - ts).total_seconds()) > PRES_FRESHNESS:
        return False, "stale_presentation"

    # firma Wallet
    cred = pres.get("credential", {})
    holder_hex = cred.get("holder_pk")
    if not holder_hex:
        return False, "missing_holder_pk"
    holder_pk = load_pubkey_hex(holder_hex)
    sig_w = pres.get("sig_wallet","")
    msg_w = json.dumps({k:v for k,v in pres.items() if k!="sig_wallet"}, sort_keys=True).encode()
    if not verify_sig(holder_pk, msg_w, sig_w):
        return False, "wallet_sig_invalid"

    # firma Issuer sulla credenziale
    sig_i = cred.get("sig_issuer","")
    signed = {k:v for k,v in cred.items() if k not in ("sig_issuer","holder_pk")}
    msg_i = json.dumps(signed, sort_keys=True).encode()
    if not verify_sig(ISSUER_PK, msg_i, sig_i):
        return False, "issuer_sig_invalid"

    # scadenza credenziale
    exp = datetime.datetime.fromisoformat(cred.get("expiration_date","").replace("Z","+00:00"))
    if now > exp:
        return False, "credential_expired"

    # challenge/audience/request_id
    nonce      = pres.get("nonce") or pres.get("challenge")
    audience   = pres.get("audience")
    request_id = pres.get("request_id")
    if not nonce or not audience or not request_id:
        return False, "missing_challenge_fields"

    con = sqlite3.connect(DB_PATH); cur = con.cursor()
    cur.execute("""SELECT challenge, audience, need_json, expires_at, used_at
                   FROM challenges WHERE request_id=?""", (request_id,))
    row = cur.fetchone()
    if row is None:
        con.close(); return False, "unknown_request_id"
    ch_db, aud_db, need_json, expires_at_str, used_at = row
    expires_at = datetime.datetime.fromisoformat(expires_at_str.replace("Z","+00:00"))
    if now > expires_at:        con.close(); return False, "challenge_expired"
    if audience != aud_db:      con.close(); return False, "audience_mismatch"
    if nonce != ch_db:          con.close(); return False, "challenge_mismatch"
    if used_at:                 con.close(); return False, "challenge_already_used"

    # need coerente
    need_emitted = json.loads(need_json)
    if sorted(need_emitted) != sorted(pres.get("need", [])):
        con.close(); return False, "need_mismatch"

    # marca challenge come usato
    cur.execute("UPDATE challenges SET used_at=? WHERE request_id=?", (_iso(now), request_id))
    con.commit(); con.close()

    # CRL: firma + freschezza obbligatorie
    crl = fetch_crl()
    if crl is None:
        return False, "crl_unavailable"

    # Verifica revoca con Merkle proof se fornita (preferita), altrimenti fallback
    mp = pres.get("merkle_proof") or {}
    cid = cred.get("credential_id")
    if "leaf_index" in mp and "path" in mp and isinstance(mp["path"], list):
        computed = _merkle_root_from_path(sha256(cid.encode()), int(mp.get("leaf_index", 0)), mp["path"])
        # Se la root calcolata combacia con quella della CRL → membership => REVOCATA
        if computed == crl.get("merkle_root"):
            return False, "credential_revoked"
        # Diversa → non membership (ok)
    else:
        # Fallback legacy: usa la lista completa se presente nella CRL
        revoked = crl.get("revoked")
        if isinstance(revoked, list) and cid in revoked:
            return False, "credential_revoked"
        # Se non c'è lista e non c'è proof → non possiamo determinare
        if not isinstance(revoked, list):
            return False, "missing_merkle_proof"

    # commitment check
    for attr,bundle in pres.get("revealed", {}).items():
        salt = bytes.fromhex(bundle.get("salt",""))
        val  = bundle.get("value","").encode()
        if sha256(salt + val).hex() != (bundle.get("comm","") or "").lower():
            return False, f"commitment_mismatch:{attr}"

    # policy enforcement
    for needed in need_emitted:
        if needed not in pres.get("revealed", {}):
            return False, "policy_unsatisfied"

    return True, "valid"

# ── Endpoints ───────────────────────────────────────────────────────────────
@app.route("/verify", methods=["POST"])
def verify():
    try:
        # Prima prova: parsing standard silenzioso
        pres = request.get_json(silent=True)

        # Se ancora None, prova a caricare il raw body (diagnostica migliore)
        if pres is None:
            raw = request.get_data(cache=False, as_text=False)
            if not raw:
                return jsonify({"error":"bad_json","message":"empty body"}), 400
            try:
                pres = json.loads(raw.decode("utf-8"))
            except Exception as e:
                app.logger.warning("Bad JSON body: %s", e)
                return jsonify({"error":"bad_json","message":str(e)}), 400

        ok, reason = verify_presentation(pres)
        resp = {"result": "valid" if ok else "invalid", "reason": reason}
        log_interaction("wallet","verifier", pres, resp, "valid" if ok else "invalid", reason)
        return jsonify(resp), (200 if ok else 400)

    except Exception as e:
        app.logger.exception("Error in /verify")
        return jsonify({"error":"internal_error","message":str(e)}), 500

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    app.run(host="0.0.0.0", port=8000, debug=False)
