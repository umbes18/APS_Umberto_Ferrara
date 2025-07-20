from flask import Flask, request, jsonify, send_file, render_template, abort
import sqlite3, uuid, datetime, os, json, hashlib, logging, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from crl_updater import CRLUpdater, CRL_PATH

app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.DEBUG)

# ---------- configurazione & costanti ----------
DB_PATH   = "/app/data/academic_records.db"            # SQLite DB condiviso
MASTER_KEY = bytes.fromhex(
    "eeda9c45718603d94759d95a5a63f67c2af24e52fc40ebb1f84b4c591910bddb"
)  # chiave segreta radice per HKDF
ISSUER_SK = ed25519.Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex("51e74d0ad3ae796a222a0a13e3619d75388dca8540df9571209311d9276ec93d")
)
ISSUER_PK_HEX = ISSUER_SK.public_key().public_bytes_raw().hex()

crl_updater = CRLUpdater(ISSUER_SK)
TEMPLATE_DASH = "dashboard.html"  # html unico riutilizzato da tutti i container

# ---------- funzioni utilità DB & logging ----------
def get_db_connection():
    """Apre connessione SQLite con Row factory (dict‑like)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def load_student_pubkey(student_id: str) -> bytes | None:
    """Ritorna la public key hex dello studente dal DB, se presente."""
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT pubkey_hex FROM students WHERE student_id=?", (student_id,))
    row = cur.fetchone(); conn.close()
    return bytes.fromhex(row["pubkey_hex"]) if row else None

def ensure_issued_creds_schema():
    """Crea la tabella issued_creds se non esiste."""
    con = get_db_connection(); cur = con.cursor()
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
    """
    Popola issued_creds leggendo i log di /issue nel DB.
    Deve essere chiamata una sola volta all’avvio, dopo ensure_issued_creds_schema().
    """
    con = get_db_connection()
    cur = con.cursor()

    # prendi tutte le risposte di issue dal log (actor_from="wallet", actor_to="issuer")
    cur.execute("""
        SELECT response
          FROM logs
         WHERE actor_to = 'issuer'
           AND response LIKE '%credential_id%'
    """)
    rows = cur.fetchall()
    inserted = 0

    for row in rows:
        try:
            resp = json.loads(row["response"])
            cid   = resp["credential_id"]
            stud  = resp["subject"]
            # se nei log hai salvato exam_name e exam_date oppure grade dentro il log originale:
            # altrimenti riprendi da resp cifrato / decifrato (ma qui ipotizziamo siano nel resp plain)
            exam  = resp.get("exam_name")
            date  = resp.get("exam_date")
            grade = resp.get("grade")
            if cid and stud:
                cur.execute("""
                    INSERT OR IGNORE INTO issued_creds
                        (credential_id, student_id, exam_name, exam_date, grade)
                    VALUES (?, ?, ?, ?, ?)
                """, (cid, stud, exam, date, grade))
                inserted += cur.rowcount
        except Exception:
            # salta righe non-JSON o log difettosi
            continue

    con.commit()
    con.close()
    app.logger.info("Backfilled %d entries into issued_creds", inserted)

# chiamala subito dopo ensure_issued_creds_schema()
ensure_issued_creds_schema()
backfill_issued_creds_from_logs()

def log_interaction(frm: str, to: str, req_obj: dict, resp_obj: dict):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs(actor_from, actor_to, request, response, created_at)
        VALUES(?,?,?,?,?)
    """, (
        frm,
        to,
        json.dumps(req_obj, sort_keys=True),
        json.dumps(resp_obj, sort_keys=True),
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    ))
    conn.commit(); conn.close()

# ------------------------------------------------------------------
# Endpoint /issue🎓 – emette credenziale firmata e cifrata
# ------------------------------------------------------------------
@app.route("/issue", methods=["POST"])
def issue_credential():
    """Flusso principale di emissione credenziale."""
    data = request.get_json()

    # 0 validate campi attesi
    required = ["student_id", "exam_name", "exam_date", "nonce", "timestamp", "signature"]
    if any(k not in data for k in required):
        return jsonify({"error": "Bad request"}), 400

    student_id   = data["student_id"]
    exam_name    = data["exam_name"]
    exam_date_req= data["exam_date"]

    # 1️⃣ verifica firma Wallet sulla richiesta
    pk_bytes = load_student_pubkey(student_id)
    if pk_bytes is None:
        return jsonify({"error": "Unknown student_id"}), 400

    msg = f"{student_id}|{exam_name}|{exam_date_req}|{data['nonce']}|{data['timestamp']}".encode()
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes).verify(bytes.fromhex(data["signature"]), msg)
    except Exception:
        return jsonify({"error": "Wallet sig verification failed"}), 400

    # 2 carica dati ufficiali dell’esame dal DB (source of truth)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(
        "SELECT exam_date, grade FROM exams WHERE student_id=? AND exam_name=? AND exam_date=?",
        (student_id, exam_name, exam_date_req)
    )
    rec = cur.fetchone(); conn.close()
    if rec is None:
        return jsonify({"error": "Exam record not found"}), 404
    exam_date, grade = rec["exam_date"], rec["grade"]

    # 3 genera metadati credenziale
    cred_id      = str(uuid.uuid4())
    now          = datetime.datetime.utcnow()
    issue_date   = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    exp_date     = (now + datetime.timedelta(days=1825)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 4 deriva chiave simmetrica K_enc con HKDF(MASTER_KEY, cred_id)
    hkdf  = HKDF(algorithm=hashes.SHA256(), length=32, salt=cred_id.encode(), info=None)
    k_enc = hkdf.derive(MASTER_KEY)
    iv    = os.urandom(12)
    aes   = AESGCM(k_enc)

    # 5 prepara payload cifrato con salt+commitment per ogni attributo
    payload: dict[str, str] = {}
    for attr, val in [("exam_name", exam_name), ("exam_date", exam_date), ("grade", grade)]:
        salt = os.urandom(16)
        comm = hashlib.sha256(salt + val.encode()).digest()
        payload[attr]             = val        # valore plain
        payload[f"salt_{attr}"]  = salt.hex() # salt rivelabile solo se necessario
        payload[f"comm_{attr}"]  = comm.hex() # commitment firmato

    ciphertext = aes.encrypt(iv, json.dumps(payload, sort_keys=True).encode(), None)

    # 6 costruisci header + firma Issuer (Ed25519) su tutto
    cred = {
        "issuer":          "Université de Rennes",
        "subject":         student_id,
        "issue_date":      issue_date,
        "expiration_date": exp_date,
        "credential_id":   cred_id,
        "iv":              iv.hex(),
        "cipher":          ciphertext.hex()
    }
    cred["sig_issuer"] = ISSUER_SK.sign(json.dumps(cred, sort_keys=True).encode()).hex()

    # log & risposta
    log_interaction("wallet", "issuer", data, cred)

    # **Nuovo: salva mapping in issued_creds**
    conn = get_db_connection();
    cur = conn.cursor()
    cur.execute("""
                INSERT INTO issued_creds(credential_id, student_id, exam_name, exam_date, grade)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    cred["credential_id"],
                    data["student_id"],
                    data["exam_name"],
                    exam_date,  # da rec["exam_date"]
                    grade  # da rec["grade"]
                ))
    conn.commit();
    conn.close()

    return jsonify(cred), 201

# ------------------------------------------------------------------
# Endpoint /revoke 🔒 – revoca credenziale, aggiorna CRL
# ------------------------------------------------------------------
@app.route("/revoke", methods=["POST"])
def revoke():
    cid = request.json.get("credential_id")
    if not cid:
        return {"error": "credential_id required"}, 400

    # --- lookup in issued_creds per student/exam/grade --------------
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT student_id, exam_name, grade
          FROM issued_creds
         WHERE credential_id = ?
    """, (cid,))
    info = cur.fetchone()
    conn.close()

    # --- revoca sulla CRL (la tua logica esistente) ------------------
    updated = crl_updater.revoke(cid)
    resp = {
        "status":    "ok" if updated else "already_revoked",
        "version":   crl_updater.crl["version"],
        "root":      crl_updater.crl["merkle_root"],
        "signature": crl_updater.crl["signature"]
    }

    # --- arricchisci JSON di request per il log ---------------------
    req_obj = {"revoke": cid}
    if info:
        req_obj.update({
            "student_id": info["student_id"],
            "exam_name":  info["exam_name"],
            "grade":      info["grade"]
        })

    log_interaction("admin", "issuer", req_obj, resp)
    return jsonify(resp), 200

# ------------------------------------------------------------------
# Endpoint /crl  🌍 – distribuisce crl.json firmato
# ------------------------------------------------------------------
@app.route("/crl", methods=["GET"])
def crl():
    # se per qualche motivo crl.json manca, rigenera sul posto
    if not os.path.exists(CRL_PATH):
        crl_updater._flush()
    try:
        return send_file(CRL_PATH, mimetype="application/json")
    except FileNotFoundError:
        abort(404, description="CRL not found")

# ------------------------------------------------------------------
# Endpoint /dashboard  📊 – mostra log Issuer
# ------------------------------------------------------------------
@app.route("/dashboard", methods=["GET"])
def dashboard():
    conn = get_db_connection(); rows = conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall(); conn.close()
    return render_template(TEMPLATE_DASH, logs=rows)

# ------------------------------------------------------------------
# Endpoint /provision  🔑 – provisioning della MASTER_KEY al Wallet
# ------------------------------------------------------------------
@app.route("/provision", methods=["GET"])
def provision_master_key():
    """
    Fornisce al Wallet la MASTER_KEY (hex) necessaria per derivare K_enc via HKDF.

    Attenzione: questo endpoint va esposto SOLO su canale TLS 1.3 con
    autenticazione mutua (client-cert) o altro meccanismo di accesso
    controllato, per evitare che terze parti ottengano la key.
    """
    # Qui, in un sistema reale, si verificherebbe l’identità del Wallet
    return jsonify({
        "master_key": MASTER_KEY.hex()
    }), 200

# ------------------------------------------------------------------
# Avvio Flask (porta 8000, debug ON nel container)
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
