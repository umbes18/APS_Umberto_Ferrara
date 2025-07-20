from flask import Flask, request, jsonify, render_template
import sqlite3, json, datetime, uuid, os, pathlib, requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519

# Inizializza Flask e specifica la cartella dei template (dashboard condivisa con Issuer)
app = Flask(__name__, template_folder="templates")

# Database paths
CRED_DB = "/app/data/wallet_credentials.db"
LOG_DB  = "/app/data/wallet_logs.db"

# Configurazione Issuer (mTLS provisioning)
ISSUER_URL      = os.getenv("ISSUER_URL", "https://issuer:8000")
CA_CERT_PATH    = os.getenv("CA_CERT_PATH", "/etc/ssl/certs/ca.crt")
WALLET_TLS_CERT = os.getenv("WALLET_TLS_CERT_PATH", "/etc/ssl/certs/wallet.crt")
WALLET_TLS_KEY  = os.getenv("WALLET_TLS_KEY_PATH", "/etc/ssl/private/wallet.key")
# Chiave privata Ed25519 per le firme (Schnorr)
KEYS_DIR = pathlib.Path(os.getenv("WALLET_KEYS_DIR", "/app/wallet_keys"))
ISSUER_PK_HEX   = os.getenv("ISSUER_PK_HEX", "")

# Carica **tutte** le chiavi private
SK_MAP: dict[str, ed25519.Ed25519PrivateKey] = {}
for key_file in KEYS_DIR.glob("stud*.key"):
    with open(key_file, "rb") as f:
        SK_MAP[key_file.stem] = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())

# Recupera MASTER_KEY dall'Issuer via mTLS
resp = requests.get(
    f"{ISSUER_URL}/provision",
    cert=(WALLET_TLS_CERT, WALLET_TLS_KEY),
    verify=CA_CERT_PATH
)
resp.raise_for_status()
MASTER_KEY = bytes.fromhex(resp.json().get("master_key", ""))

# Funzione di utilità: log delle interazioni
def log_interaction(frm: str, to: str, req_obj: dict, resp_obj: dict):
    con = sqlite3.connect(LOG_DB)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_from TEXT,
            actor_to TEXT,
            request TEXT,
            response TEXT,
            created_at TEXT
        )"""
    )
    cur.execute(
        "INSERT INTO logs(actor_from,actor_to,request,response,created_at) VALUES(?,?,?,?,?)",
        (
            frm,
            to,
            json.dumps(req_obj),
            json.dumps(resp_obj),
            datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    )
    con.commit()
    con.close()

# Funzione di utilità: memorizza credenziale e payload decrittato
def store_credential(cred: dict, payload: dict):
    con = sqlite3.connect(CRED_DB)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id TEXT UNIQUE,
            issuer TEXT,
            subject TEXT,
            issue_date TEXT,
            expiration_date TEXT,
            payload TEXT
        )"""
    )
    cur.execute(
        "INSERT OR REPLACE INTO credentials(credential_id,issuer,subject,issue_date,expiration_date,payload) VALUES(?,?,?,?,?,?)",
        (
            cred["credential_id"],
            cred["issuer"],
            cred["subject"],
            cred["issue_date"],
            cred["expiration_date"],
            json.dumps(payload)
        )
    )
    con.commit()
    con.close()

# ------------------------------------------------------------------
# Endpoint /request – invio richiesta di emissione
# ------------------------------------------------------------------
@app.route("/request", methods=["POST"])
def request_credential():
    data = request.get_json()
    student_id = data["student_id"]

    wallet_sk = SK_MAP.get(student_id)
    if wallet_sk is None:
        return jsonify({"error": "unknown student_id"}), 400

    nonce = uuid.uuid4().hex
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Firma la richiesta con la chiave dello studente
    msg = f"{student_id}|{data['exam_name']}|{data['exam_date']}|{nonce}|{ts}".encode()
    sig = wallet_sk.sign(msg).hex()
    req_obj = {
        "student_id": data["student_id"],
        "exam_name":  data["exam_name"],
        "exam_date":  data["exam_date"],
        "nonce":      nonce,
        "timestamp":  ts,
        "signature":  sig
    }

    # Chiamata all'Issuer via mTLS
    resp = requests.post(
        f"{ISSUER_URL}/issue",
        json=req_obj,
        cert=(WALLET_TLS_CERT, WALLET_TLS_KEY),
        verify=CA_CERT_PATH
    )
    resp.raise_for_status()
    cred = resp.json()

    # Verifica firma Issuer
    issig = cred.pop("sig_issuer", "")
    ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ISSUER_PK_HEX)) \
        .verify(bytes.fromhex(issig), json.dumps(cred, sort_keys=True).encode())

    # Deriva K_enc e decripta payload
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=cred["credential_id"].encode(), info=None)
    k_enc = hkdf.derive(MASTER_KEY)
    aes = AESGCM(k_enc)
    plaintext = aes.decrypt(
        bytes.fromhex(cred["iv"]),
        bytes.fromhex(cred["cipher"]), None
    )
    payload = json.loads(plaintext)

    # Salva credenziale e logga
    store_credential(cred, payload)
    log_interaction("wallet", "issuer", req_obj, cred)
    return jsonify(cred), 200

# ------------------------------------------------------------------
# Endpoint /present – presentazione selettiva
# ------------------------------------------------------------------
@app.route("/present", methods=["POST"])
def present_credential():
    data    = request.get_json()
    cred_id = data.get("credential_id")
    need    = data.get("need", [])

    # 1) recupera payload decriptato + subject
    con = sqlite3.connect(CRED_DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(
        "SELECT payload, subject FROM credentials WHERE credential_id=?",
        (cred_id,)
    )
    row = cur.fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Unknown credential_id"}), 404

    stored         = json.loads(row["payload"])
    student_id     = row["subject"]                 # <-- ecco chi firma
    wallet_sk      = SK_MAP.get(student_id)         # sceglie la chiave corretta
    if wallet_sk is None:
        return jsonify({"error": "unknown student_id"}), 400

    # 2) costruisce la presentation
    pres = {"credential_id": cred_id, "revealed": {}}
    for attr in need:
        if attr in stored:
            pres["revealed"][attr] = {
                "value": stored[attr],
                "salt":  stored.get(f"salt_{attr}"),
                "comm":  stored.get(f"comm_{attr}")
            }

    # 3) nonce, timestamp, firma con la chiave dello studente
    pres["nonce"]      = uuid.uuid4().hex
    pres["timestamp"]  = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    msg                = json.dumps(pres, sort_keys=True).encode()
    pres["sig_wallet"] = wallet_sk.sign(msg).hex()

    log_interaction("wallet", "verifier", data, pres)
    return jsonify(pres), 200

# ------------------------------------------------------------------
# Dashboard – mostra log delle interazioni
# ------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    con = sqlite3.connect(LOG_DB)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    con.close()
    return render_template("dashboard.html", logs=rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
