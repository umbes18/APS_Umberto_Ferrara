# issuer/main.py
from flask import Flask, request, jsonify, send_file, render_template, abort
import sqlite3, uuid, datetime, os, json, hashlib, logging, time
from urllib.parse import unquote
from typing import Optional, Tuple, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519

from crypto_utils import sha256, load_pubkey_hex, verify_sig
from crl_updater import CRLUpdater, CRL_PATH

app = Flask(__name__, template_folder="templates")

# ---------------- Anti‐replay & error handling ----------------
REPLAY_WINDOW = 600  # secondi
_seen = {}           # digest(request_body) -> last_timestamp

def _error():
    return jsonify({"error": "request_rejected"}), 400

# Se vuoi rendere OBBLIGATORIO il pinning (client-cert richiesto a livello app),
# esporta REQUIRE_CLIENT_CERT=1 nell'ambiente del container issuer.
REQUIRE_CLIENT_CERT = os.getenv("REQUIRE_CLIENT_CERT", "0") == "1"

# ---------------- configurazione & costanti --------------------
DB_PATH       = "/app/data/academic_records.db"
MASTER_KEY    = bytes.fromhex(
    "eeda9c45718603d94759d95a5a63f67c2af24e52fc40ebb1f84b4c591910bddb"
)
ISSUER_SK     = ed25519.Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex(
        "51e74d0ad3ae796a222a0a13e3619d75388dca8540df9571209311d9276ec93d"
    )
)
# public key in hex per la CRL‐signature verification se servisse
ISSUER_PK_HEX = ISSUER_SK.public_key().public_bytes_raw().hex()

crl_updater   = CRLUpdater(ISSUER_SK)
crl_updater._flush()
TEMPLATE_DASH = "dashboard.html"


# ---------------- funzioni utilità DB & logging ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def load_student_pubkey(student_id: str) -> bytes | None:
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("SELECT pubkey_hex FROM students WHERE student_id=?", (student_id,))
    row = cur.fetchone()
    conn.close()
    return bytes.fromhex(row["pubkey_hex"]) if row else None

def ensure_issued_creds_schema():
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS issued_creds(
            credential_id TEXT PRIMARY KEY,
            student_id    TEXT,
            exam_name     TEXT,
            exam_date     TEXT,
            grade         TEXT
        )
    """)
    # NEW: tabella per il pinning del certificato client
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wallet_pins(
            student_id TEXT PRIMARY KEY,
            cert_fpr   TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    con.commit(); con.close()

def backfill_issued_creds_from_logs():
    con = get_db_connection(); cur = con.cursor()
    cur.execute("""
        SELECT response FROM logs
        WHERE actor_to='issuer' AND response LIKE '%credential_id%'
    """)
    rows = cur.fetchall()
    inserted = 0
    for row in rows:
        try:
            resp = json.loads(row["response"])
            # Compatibile con risposta singola o con array "credentials"
            if "credentials" in resp and isinstance(resp["credentials"], list):
                for cred in resp["credentials"]:
                    cid  = cred.get("credential_id")
                    stud = cred.get("subject")
                    if cid and stud:
                        cur.execute("""
                            INSERT OR IGNORE INTO issued_creds(
                                credential_id, student_id, exam_name, exam_date, grade
                            ) VALUES(?,?,?,?,?)
                        """, (cid, stud, None, None, None))
                        inserted += cur.rowcount
            else:
                cid  = resp.get("credential_id")
                stud = resp.get("subject")
                exam = resp.get("exam_name")
                date = resp.get("exam_date")
                grade= resp.get("grade")
                if cid and stud:
                    cur.execute("""
                        INSERT OR IGNORE INTO issued_creds(
                            credential_id, student_id, exam_name, exam_date, grade
                        ) VALUES(?,?,?,?,?)
                    """, (cid, stud, exam, date, grade))
                    inserted += cur.rowcount
        except Exception:
            continue
    con.commit(); con.close()
    app.logger.info("Backfilled %d entries into issued_creds", inserted)

def log_interaction(frm: str, to: str, req_obj: dict, resp_obj: dict):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs(actor_from, actor_to, request, response, created_at)
        VALUES(?,?,?,?,?)
    """, (
        frm, to,
        json.dumps(req_obj, sort_keys=True),
        json.dumps(resp_obj, sort_keys=True),
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    ))
    conn.commit(); conn.close()

ensure_issued_creds_schema()
backfill_issued_creds_from_logs()

# ---------------- Pinning helpers ----------------
def _extract_client_cert_fingerprint() -> Optional[str]:
    """
    Prova a ottenere la fingerprint del certificato client (hex lowercase senza ':').
    Compatibile con scenari senza reverse proxy:
    - X-Client-Cert-Fingerprint: impronta già calcolata (es. dal tuo ambiente)
    - X-Client-Cert: PEM url-escaped, da cui calcoliamo SHA-256 sul DER
    Se non troviamo nulla, ritorna None (compatibilità col setup attuale).
    """
    fpr_hdr = request.headers.get("X-Client-Cert-Fingerprint")
    if fpr_hdr:
        return fpr_hdr.replace(":", "").lower()

    pem_esc = request.headers.get("X-Client-Cert")
    if pem_esc:
        try:
            pem = unquote(pem_esc)
            cert = x509.load_pem_x509_certificate(pem.encode())
            der  = cert.public_bytes(serialization.Encoding.DER)
            return hashlib.sha256(der).hexdigest()
        except Exception:
            app.logger.warning("X-Client-Cert presente ma non parsabile")
            return None
    return None

def _pin_check_and_set(student_id: str, fpr_hex: str) -> Tuple[bool, str]:
    """
    Se non esiste un pin per lo student_id -> crea pin (prima associazione).
    Se esiste -> match => ok, mismatch => blocca.
    """
    con = get_db_connection(); cur = con.cursor()
    cur.execute("SELECT cert_fpr FROM wallet_pins WHERE student_id=?", (student_id,))
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO wallet_pins(student_id, cert_fpr, created_at) VALUES(?,?,?)",
            (student_id, fpr_hex.lower(), datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
        )
        con.commit(); con.close()
        return True, "pinned_first_time"
    pinned = row["cert_fpr"].lower()
    con.close()
    if pinned == fpr_hex.lower():
        return True, "pin_match"
    return False, "wallet_cert_mismatch"

# ---------------- AAD helper (canonico) ----------------
def _build_aad_bytes(issuer: str, subject: str, issue_date: str,
                     expiration_date: str, credential_id: str) -> bytes:
    """
    Costruisce AAD come JSON canonico degli header, così Wallet e Issuer producono
    esattamente lo stesso byte-stream.
    """
    aad = {
        "issuer":          issuer,
        "subject":         subject,
        "issue_date":      issue_date,
        "expiration_date": expiration_date,
        "credential_id":   credential_id
    }
    # JSON canonico: chiavi ordinate, separatori compatti
    return json.dumps(aad, sort_keys=True, separators=(",", ":")).encode()

# ------------------------------------------------------------------
# Endpoint /issue – emette TUTTE le credenziali firmate e cifrate (con AAD)
# ------------------------------------------------------------------
@app.route("/issue", methods=["POST"])
def issue_credential():
    # Anti‐replay: digest della richiesta
    body = request.get_data()
    h    = hashlib.sha256(body).hexdigest()
    now  = time.time()
    # purge entry scadute
    for k,ts in list(_seen.items()):
        if now - ts > REPLAY_WINDOW:
            _seen.pop(k)
    if h in _seen:
        return _error()
    _seen[h] = now

    data = request.get_json()
    # campi obbligatori (N.B. niente exam_name/date nella richiesta!)
    required = ["student_id","nonce","timestamp","signature"]
    if any(k not in data for k in required):
        return jsonify({"error":"Bad request"}), 400

    # Verifica firma del Wallet (Holder) sulla richiesta
    pk_hex = load_student_pubkey(data["student_id"])
    if pk_hex is None:
        return _error()
    holder_pk = load_pubkey_hex(pk_hex.hex())
    msg = f"{data['student_id']}|{data['nonce']}|{data['timestamp']}".encode()
    if not verify_sig(holder_pk, msg, data["signature"]):
        return _error()

    # Pinning del certificato client: compatibile con setup attuale
    fpr = _extract_client_cert_fingerprint()
    if fpr:
        ok, pin_status = _pin_check_and_set(data["student_id"], fpr)
        if not ok:
            resp = {"error":"wallet_cert_mismatch"}
            log_interaction("wallet","issuer", {"student_id": data["student_id"], "fpr": fpr}, resp)
            return jsonify(resp), 401
    else:
        # fingerprint non disponibile: se obbligatoria, blocca; altrimenti continua (compatibilità)
        if REQUIRE_CLIENT_CERT:
            return jsonify({"error":"client_cert_missing"}), 401
        pin_status = "not_provided"

    # Recupera TUTTI gli esami in DB per lo studente
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        "SELECT exam_name, exam_date, grade FROM exams WHERE student_id=?",
        (data["student_id"],)
    )
    records = cur.fetchall(); conn.close()
    if not records:
        return _error()

    # Genera tutte le credenziali per lo studente (AAD in AES-GCM)
    credentials = []
    now_dt   = datetime.datetime.utcnow()
    issue_dt = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    exp_dt   = (now_dt + datetime.timedelta(days=1825)).strftime("%Y-%m-%dT%H:%M:%SZ")
    subject  = data["student_id"]
    issuer   = "Université de Rennes"

    conn2 = get_db_connection(); cur2 = conn2.cursor()
    for rec in records:
        cred_id  = str(uuid.uuid4())

        # Deriva chiave e cifra payload con AEAD AESGCM + AAD canonico
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=cred_id.encode(), info=None)
        k_enc = hkdf.derive(MASTER_KEY)
        aes   = AESGCM(k_enc)
        iv    = os.urandom(12)

        # Payload con salt e commitment per ogni attributo
        payload = {}
        for attr, val in [
            ("exam_name", rec["exam_name"]),
            ("exam_date", rec["exam_date"]),
            ("grade",     rec["grade"])
        ]:
            salt = os.urandom(16)
            comm = hashlib.sha256(salt + val.encode()).digest()
            payload[attr]            = val
            payload[f"salt_{attr}"]  = salt.hex()
            payload[f"comm_{attr}"]  = comm.hex()

        # AAD: header canonici della credenziale
        aad_bytes = _build_aad_bytes(issuer, subject, issue_dt, exp_dt, cred_id)

        ciphertext = aes.encrypt(iv, json.dumps(payload, sort_keys=True).encode(), aad_bytes)

        # Costruisci JSON della credenziale e firma dell’Issuer
        cred = {
            "issuer":          issuer,
            "subject":         subject,
            "issue_date":      issue_dt,
            "expiration_date": exp_dt,
            "credential_id":   cred_id,
            "iv":              iv.hex(),
            "cipher":          ciphertext.hex()
        }
        # Firma Ed25519 dell'intero JSON (header + body cifrato)
        cred["sig_issuer"] = ISSUER_SK.sign(
            json.dumps(cred, sort_keys=True).encode()
        ).hex()

        credentials.append(cred)

        # Persist minima per amministrazione/revoca
        cur2.execute(
            "INSERT OR IGNORE INTO issued_creds(credential_id, student_id, exam_name, exam_date, grade)"
            " VALUES(?,?,?,?,?)",
            (cred_id, subject, rec["exam_name"], rec["exam_date"], rec["grade"])
        )
    conn2.commit(); conn2.close()

    resp_obj = {"credentials": credentials, "pin_status": pin_status}
    log_interaction("wallet","issuer", data, resp_obj)
    return jsonify(resp_obj), 201


# ------------------------------------------------------------------
# Endpoint /proof/<credential_id> – Merkle‐proof per revoca
# ------------------------------------------------------------------
@app.route("/proof/<cid>", methods=["GET"])
def proof(cid):
    # Usa CRLUpdater già esistente per ottenere lo stato corrente
    crl = crl_updater.crl
    leaves = sorted(crl["revoked"])
    hashes = [sha256(x.encode()) for x in leaves]
    try:
        idx = leaves.index(cid)
    except ValueError:
        # non revocato: includi foglia fittizia per proof di non‐inclusione
        leaves.append(cid)
        hashes.append(sha256(cid.encode()))
        leaves, hashes = zip(*sorted(zip(leaves, hashes)))
        idx = list(leaves).index(cid)

    # Costruzione del path Merkle
    path = []
    lvl  = list(hashes)
    i    = idx
    while len(lvl) > 1:
        sib = i ^ 1
        if sib < len(lvl):
            path.append(lvl[sib].hex())
        else:
            path.append(lvl[i].hex())
        # risali di un livello
        next_lvl = []
        for j in range(0, len(lvl), 2):
            left  = lvl[j]
            right = lvl[j+1] if j+1 < len(lvl) else lvl[j]
            next_lvl.append(sha256(left+right))
        i   //= 2
        lvl  = next_lvl

    return jsonify({
        "leaf_index": idx,
        "path":       path,
        "root":       crl["merkle_root"]
    })


# ------------------------------------------------------------------
# Endpoint /revoke – revoca credenziale e aggiorna CRL
# ------------------------------------------------------------------
@app.route("/revoke", methods=["POST"])
def revoke():
    cid = request.json.get("credential_id")
    if not cid:
        return jsonify({"error":"credential_id required"}), 400

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        "SELECT student_id, exam_name, grade FROM issued_creds WHERE credential_id=?",
        (cid,)
    )
    info = cur.fetchone(); conn.close()

    updated = crl_updater.revoke(cid)
    crl_updater._flush()

    resp = {
        "status":      "ok" if updated else "already_revoked",
        "version":     crl_updater.crl["version"],
        "merkle_root": crl_updater.crl["merkle_root"],
        "timestamp":   crl_updater.crl["timestamp"],
        "signature":   crl_updater.crl["signature"]
    }

    req_obj = {"revoke": cid}
    if info:
        req_obj.update({
            "student_id": info["student_id"],
            "exam_name":  info["exam_name"],
            "grade":      info["grade"]
        })
    log_interaction("admin","issuer", req_obj, resp)
    return jsonify(resp), 200


# ------------------------------------------------------------------
# Endpoint /crl – distribuisce crl.json firmato
# ------------------------------------------------------------------
@app.route("/crl", methods=["GET"])
def crl():
    # Force roll: aggiorna timestamp, versione, firma e scrive su file
    crl_updater._recompute()
    crl_updater._flush()
    return send_file(CRL_PATH, mimetype="application/json")

# ------------------------------------------------------------------
# Endpoint /provision – provisioning MASTER_KEY
# ------------------------------------------------------------------
@app.route("/provision", methods=["GET"])
def provision_master_key():
    return jsonify({"master_key": MASTER_KEY.hex()}), 200


# ------------------------------------------------------------------
# Avvio Flask (solo per testing rapido) — TLS come prima (nessun cambio)
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
