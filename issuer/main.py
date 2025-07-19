from flask import Flask, request, jsonify
from flask import render_template
import sqlite3, uuid, datetime, os, json, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
import logging
app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.DEBUG)
# -------------------------------------------------------------------
# Configurazione chiavi e database
# -------------------------------------------------------------------

# Path al DB SQLite montato nel container
DB_PATH = "/app/data/academic_records.db"
# Master key segreta dell'Issuer per HKDF (32 byte raw)
MASTER_KEY = bytes.fromhex("eeda9c45718603d94759d95a5a63f67c2af24e52fc40ebb1f84b4c591910bddb")
# Chiave privata Ed25519 dell'Issuer (32 byte raw)
ISSUER_PRIVKEY_BYTES = bytes.fromhex( "51e74d0ad3ae796a222a0a13e3619d75388dca8540df9571209311d9276ec93d")
ISSUER_SK = ed25519.Ed25519PrivateKey.from_private_bytes(ISSUER_PRIVKEY_BYTES)

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

# Helper: log_interaction
def log_interaction(frm: str, to: str, req_obj: dict, resp_obj: dict):
    """Salva in logs ogni richiesta e risposta tra attori."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO logs(actor_from, actor_to, request, response, created_at)
           VALUES(?,?,?,?,?)""",
        (
            frm,
            to,
            json.dumps(req_obj, sort_keys=True),
            json.dumps(resp_obj, sort_keys=True),
            datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    )
    conn.commit()
    conn.close()
@app.route("/issue", methods=["POST"])
def issue_credential():
    data = request.get_json()
    # --- 0. Estrai i campi firmati ---
    try:
        student_id = data["student_id"]
        exam_name  = data["exam_name"]
        exam_date_req = data["exam_date"]
        nonce      = data["nonce"]
        ts         = data["timestamp"]
        sig_hex    = data["signature"]
    except KeyError:
        return jsonify({"error": "Bad request, missing fields"}), 400

    # --- 1. Verifica la firma del Wallet sul Request (student_id|exam_name|exam_date|nonce|ts) ---
    pk_bytes = load_student_pubkey(student_id)
    if pk_bytes is None:
        return jsonify({"error": "Unknown student_id"}), 400
    # DEBUG: Log the public key, signature and message before verification
    msg_str = f"{student_id}|{exam_name}|{exam_date_req}|{nonce}|{ts}"
    app.logger.debug(f"Wallet pubkey hex: {pk_bytes.hex()}")
    app.logger.debug(f"Incoming signature hex: {sig_hex}")
    app.logger.debug(f"Message to verify: {msg_str}")
    try:
        verify_key = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
        msg = msg_str.encode("utf-8")
        verify_key.verify(bytes.fromhex(sig_hex), msg)
    except Exception as e:
        app.logger.exception("Wallet signature verification failed")
        return jsonify({"error": "Wallet signature verification failed"}), 400

    # --- 2. Recupera dal DB i dati ufficiali dell'esame (exam_date e grade) ---
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute(
        "SELECT exam_date, grade FROM exams "
        "WHERE student_id=? AND exam_name=? AND exam_date=?",
        (student_id, exam_name, exam_date_req)
    )
    rec = cur.fetchone()
    conn.close()
    if rec is None:
        return jsonify({"error": "Exam record not found"}), 404

    # Usiamo i valori dal DB
    exam_date = rec["exam_date"]
    grade     = rec["grade"]

    # --- 3. Genera credential_id + timestamps ---
    cred_id    = str(uuid.uuid4())
    now        = datetime.datetime.utcnow()
    issue_date = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    exp_date   = (now + datetime.timedelta(days=1825)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # --- 4. Deriva K_enc via HKDF(master_key, cred_id) e IV ---
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=cred_id.encode("utf-8"), info=None)
    key_enc  = hkdf.derive(MASTER_KEY)
    aesgcm   = AESGCM(key_enc)
    iv_bytes = os.urandom(12)

    # --- 5. Costruisci il payload con salt_attr/comm_attr usando i valori UFFICIALI ---
    payload = {}
    for attr, val in [("exam_name", exam_name),
                      ("exam_date", exam_date),
                      ("grade",     grade)]:
        salt = os.urandom(16)
        h    = hashlib.sha256(); h.update(salt + val.encode("utf-8"))
        comm = h.digest()
        payload[attr]           = val
        payload[f"salt_{attr}"] = salt.hex()
        payload[f"comm_{attr}"] = comm.hex()

    # --- 6. Serializza e cifra il payload ---
    plaintext   = json.dumps(payload, sort_keys=True).encode("utf-8")
    cipher_blob = aesgcm.encrypt(iv_bytes, plaintext, None)

    # --- 7. Componi la credenziale JSON in chiaro + firma Issuer ---
    cred = {
        "issuer":          "Université de Rennes",
        "subject":         student_id,
        "issue_date":      issue_date,
        "expiration_date": exp_date,
        "credential_id":   cred_id,
        "iv":              iv_bytes.hex(),
        "cipher":          cipher_blob.hex()
    }
    to_sign    = json.dumps(cred, sort_keys=True).encode("utf-8")
    sig_issuer = ISSUER_SK.sign(to_sign)
    cred["sig_issuer"] = sig_issuer.hex()
    # Log the interaction Wallet → Issuer
    log_interaction(
        frm="wallet",
        to="issuer",
        req_obj=data,
        resp_obj=cred
    )
    return jsonify(cred), 201


# Dashboard endpoint
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Mostra tutte le interazioni registrate."""
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("dashboard.html", logs=rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)