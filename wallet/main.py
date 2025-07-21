from flask import Flask, request, jsonify, render_template
import sqlite3, json, datetime, uuid, os, pathlib, requests, logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519

app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.INFO)

# -----------------------------------------------------------------
# Config
# -----------------------------------------------------------------
CRED_DB         = "/app/data/wallet_credentials.db"
LOG_DB          = "/app/data/wallet_logs.db"
ISSUER_URL      = os.getenv("ISSUER_URL", "https://issuer:8000")
CA_CERT_PATH    = os.getenv("CA_CERT_PATH", "/etc/ssl/certs/ca.crt")
WALLET_TLS_CERT = os.getenv("WALLET_TLS_CERT_PATH", "/etc/ssl/certs/wallet.crt")
WALLET_TLS_KEY  = os.getenv("WALLET_TLS_KEY_PATH", "/etc/ssl/private/wallet.key")
KEYS_DIR        = pathlib.Path(os.getenv("WALLET_KEYS_DIR", "/app/wallet_keys"))
ISSUER_PK_HEX   = os.getenv("ISSUER_PK_HEX", "")

# -----------------------------------------------------------------
# Wallet keypairs
# -----------------------------------------------------------------
SK_MAP = {}
for key_file in KEYS_DIR.glob("stud*.key"):
    SK_MAP[key_file.stem] = ed25519.Ed25519PrivateKey.from_private_bytes(key_file.read_bytes())

# -----------------------------------------------------------------
# Fetch MASTER_KEY from issuer
# -----------------------------------------------------------------
resp = requests.get(
    f"{ISSUER_URL}/provision",
    cert=(WALLET_TLS_CERT, WALLET_TLS_KEY),
    verify=CA_CERT_PATH
)
resp.raise_for_status()
MASTER_KEY = bytes.fromhex(resp.json()["master_key"])

# -----------------------------------------------------------------
# Database schema helpers
# -----------------------------------------------------------------
def ensure_credentials_schema():
    con = sqlite3.connect(CRED_DB)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS credentials(
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id   TEXT UNIQUE,
            issuer          TEXT,
            subject         TEXT,
            issue_date      TEXT,
            expiration_date TEXT,
            sig_issuer      TEXT,
            iv              TEXT,
            cipher          TEXT,
            payload         TEXT
        )
    """)
    # Add columns if missing (migrations)
    cur.execute("PRAGMA table_info(credentials)")
    cols = {row[1] for row in cur.fetchall()}
    for col in ("iv","cipher"):
        if col not in cols:
            cur.execute(f"ALTER TABLE credentials ADD COLUMN {col} TEXT")
    con.commit()
    con.close()

def ensure_logs_schema():
    con = sqlite3.connect(LOG_DB)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_from  TEXT,
            actor_to    TEXT,
            request     TEXT,
            response    TEXT,
            created_at  TEXT
        )
    """)
    con.commit()
    con.close()

ensure_credentials_schema()
ensure_logs_schema()

# -----------------------------------------------------------------
# Logging helper
# -----------------------------------------------------------------
def log_interaction(frm, to, req_obj, resp_obj):
    con = sqlite3.connect(LOG_DB)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO logs(actor_from,actor_to,request,response,created_at)
        VALUES (?,?,?,?,?)
    """, (
        frm, to,
        json.dumps(req_obj, sort_keys=True),
        json.dumps(resp_obj, sort_keys=True),
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    ))
    con.commit()
    con.close()

# -----------------------------------------------------------------
# Store credential (with iv & cipher)
# -----------------------------------------------------------------
def store_credential(cred: dict, payload: dict) -> None:
    con = sqlite3.connect(CRED_DB)
    cur = con.cursor()
    cur.execute("""INSERT OR REPLACE INTO credentials
          (credential_id, issuer, subject,
           issue_date, expiration_date,
           sig_issuer, iv, cipher, payload)
          VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            cred["credential_id"],
            cred["issuer"],
            cred["subject"],
            cred["issue_date"],
            cred["expiration_date"],
            cred["sig_issuer"],
            cred["iv"],
            cred["cipher"],
            json.dumps(payload)
        )
    )
    con.commit()
    con.close()

# -----------------------------------------------------------------
# /request – chiedi credenziale all’Issuer
# -----------------------------------------------------------------
@app.post("/request")
def request_credential():
    data = request.get_json(force=True)
    student_id = data.get("student_id")
    wallet_sk  = SK_MAP.get(student_id)
    if wallet_sk is None:
        return {"error":"unknown student_id"}, 400

    nonce = uuid.uuid4().hex
    ts    = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    msg   = f"{student_id}|{data['exam_name']}|{data['exam_date']}|{nonce}|{ts}".encode()
    sig   = wallet_sk.sign(msg).hex()

    req_obj = {**data, "nonce":nonce, "timestamp":ts, "signature":sig}
    try:
        r = requests.post(
            f"{ISSUER_URL}/issue",
            json=req_obj,
            cert=(WALLET_TLS_CERT, WALLET_TLS_KEY),
            verify=CA_CERT_PATH
        )
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        # cattura errori dell'Issuer e restituisci JSON ben formato
        try:
            error_body = r.json()
        except Exception:
            error_body = {"error": "richiesta credenziale errata"}
        log_interaction("wallet", "issuer", req_obj, error_body)
        return jsonify({
            "error": "richiesta credenziale errata",
            "details": error_body
        }), r.status_code

    cred = r.json()

    # verifica firma Issuer
    to_verify = {k:v for k,v in cred.items() if k!="sig_issuer"}
    ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ISSUER_PK_HEX)) \
        .verify(bytes.fromhex(cred["sig_issuer"]),
                json.dumps(to_verify, sort_keys=True).encode())

    # decifra payload
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=cred["credential_id"].encode(), info=None)
    k_enc = hkdf.derive(MASTER_KEY)
    aes   = AESGCM(k_enc)
    payload = json.loads(aes.decrypt(
        bytes.fromhex(cred["iv"]),
        bytes.fromhex(cred["cipher"]), None
    ))

    store_credential(cred, payload)
    log_interaction("wallet","issuer",req_obj,cred)
    return jsonify(cred), 200

# -----------------------------------------------------------------
# /present – costruisci presentation per il Verifier
# -----------------------------------------------------------------
@app.post("/present")
def present_credential():
    data    = request.get_json(force=True)
    cred_id = data.get("credential_id")
    need    = data.get("need", [])

    con = sqlite3.connect(CRED_DB); con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM credentials WHERE credential_id=?", (cred_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return {"error":"unknown credential_id"}, 404

    payload   = json.loads(row["payload"])
    wallet_sk = SK_MAP[row["subject"]]

    cred_meta = {
        "issuer":          row["issuer"],
        "subject":         row["subject"],
        "issue_date":      row["issue_date"],
        "expiration_date": row["expiration_date"],
        "credential_id":   cred_id,
        "iv":              row["iv"],
        "cipher":          row["cipher"],
        "holder_pk":       wallet_sk.public_key().public_bytes(
                                serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw
                          ).hex(),
        "sig_issuer":      row["sig_issuer"]
    }

    revealed = {
        attr: {
            "value": payload[attr],
            "salt":  payload.get(f"salt_{attr}"),
            "comm":  payload.get(f"comm_{attr}")
        }
        for attr in need if attr in payload
    }

    pres = {
        "credential": cred_meta,
        "need":       need,
        "revealed":   revealed,
        "nonce":      uuid.uuid4().hex,
        "timestamp":  datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    pres["sig_wallet"] = wallet_sk.sign(
        json.dumps(pres, sort_keys=True).encode()
    ).hex()

    log_interaction("wallet","verifier",data,pres)
    return jsonify(pres), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
