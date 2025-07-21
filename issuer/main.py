from flask import Flask, request, jsonify, send_file, render_template, abort
import sqlite3, uuid, datetime, os, json, hashlib, logging, time
from cryptography.hazmat.primitives import hashes
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


# ------------------------------------------------------------------
# Endpoint /issue – emette credenziale firmata e cifrata
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
    # campi obbligatori
    required = ["student_id","exam_name","exam_date","nonce","timestamp","signature"]
    if any(k not in data for k in required):
        return jsonify({"error":"Bad request"}), 400

    # Verifica firma del Wallet (Holder)
    pk_hex = load_student_pubkey(data["student_id"])
    if pk_hex is None:
        return _error()
    holder_pk = load_pubkey_hex(pk_hex.hex())
    msg = f"{data['student_id']}|{data['exam_name']}|{data['exam_date']}|{data['nonce']}|{data['timestamp']}".encode()
    if not verify_sig(holder_pk, msg, data["signature"]):
        return _error()

    # Controlla esistenza esame in DB
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        "SELECT exam_name, exam_date, grade FROM exams WHERE student_id=? AND exam_name=? AND exam_date=?",
        (data["student_id"], data["exam_name"], data["exam_date"])
    )
    rec = cur.fetchone(); conn.close()
    if rec is None:
        return _error()

    # Generazione metadati credenziale
    cred_id  = str(uuid.uuid4())
    now_dt   = datetime.datetime.utcnow()
    issue_dt = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    exp_dt   = (now_dt + datetime.timedelta(days=1825)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Deriva chiave e cifra payload con AEAD AESGCM
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=cred_id.encode(), info=None)
    k_enc = hkdf.derive(MASTER_KEY)
    aes   = AESGCM(k_enc)
    iv    = os.urandom(12)

    # Costruisci payload con salt e comm per ogni attributo
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

    ciphertext = aes.encrypt(iv, json.dumps(payload, sort_keys=True).encode(), None)

    # Costruisci JSON della credenziale e firma dell’Issuer
    cred = {
        "issuer":          "Université de Rennes",
        "subject":         data["student_id"],
        "issue_date":      issue_dt,
        "expiration_date": exp_dt,
        "credential_id":   cred_id,
        "iv":              iv.hex(),
        "cipher":          ciphertext.hex()
    }
    cred["sig_issuer"] = ISSUER_SK.sign(
        json.dumps(cred, sort_keys=True).encode()
    ).hex()

    # Log e persist credenziale
    log_interaction("wallet","issuer", data, cred)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO issued_creds(credential_id, student_id, exam_name, exam_date, grade)"
        " VALUES(?,?,?,?,?)",
        (cred_id, data["student_id"], data["exam_name"], data["exam_date"], rec["grade"])
    )
    conn.commit(); conn.close()

    return jsonify(cred), 201


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
    if not os.path.exists(CRL_PATH):
        crl_updater._flush()
    return send_file(CRL_PATH, mimetype="application/json")


# ------------------------------------------------------------------
# Endpoint /provision – provisioning MASTER_KEY
# ------------------------------------------------------------------
@app.route("/provision", methods=["GET"])
def provision_master_key():
    return jsonify({"master_key": MASTER_KEY.hex()}), 200


# ------------------------------------------------------------------
# Avvio Flask (solo per testing rapido)
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
