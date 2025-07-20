from flask import Flask, request, jsonify, render_template
import sqlite3, json, datetime, uuid, os, pathlib, requests, logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519

# ----------------------------------------------------------------- Flask & log
app = Flask(__name__, template_folder="templates")
app.logger.setLevel(logging.INFO)

# ----------------------------------------------------------------- Config
CRED_DB = "/app/data/wallet_credentials.db"
LOG_DB  = "/app/data/wallet_logs.db"

ISSUER_URL      = os.getenv("ISSUER_URL", "https://issuer:8000")
CA_CERT_PATH    = os.getenv("CA_CERT_PATH",   "/etc/ssl/certs/ca.crt")
WALLET_TLS_CERT = os.getenv("WALLET_TLS_CERT_PATH", "/etc/ssl/certs/wallet.crt")
WALLET_TLS_KEY  = os.getenv("WALLET_TLS_KEY_PATH",  "/etc/ssl/private/wallet.key")
KEYS_DIR        = pathlib.Path(os.getenv("WALLET_KEYS_DIR", "/app/wallet_keys"))
ISSUER_PK_HEX   = os.getenv("ISSUER_PK_HEX", "")

# ----------------------------------------------------------------- Chiavi wallet
SK_MAP: dict[str, ed25519.Ed25519PrivateKey] = {}
for key_file in KEYS_DIR.glob("stud*.key"):
    with open(key_file, "rb") as f:
        SK_MAP[key_file.stem] = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())

PK_MAP = {
    sid: sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    for sid, sk in SK_MAP.items()
}

# ----------------------------------------------------------------- MASTER_KEY (provisioning)
resp = requests.get(
    f"{ISSUER_URL}/provision",
    cert=(WALLET_TLS_CERT, WALLET_TLS_KEY),
    verify=CA_CERT_PATH,
)
resp.raise_for_status()
MASTER_KEY = bytes.fromhex(resp.json()["master_key"])

# ----------------------------------------------------------------- DB helpers
def ensure_credentials_schema() -> None:
    """Crea (o migra) la tabella credentials aggiungendo iv/cipher se mancano."""
    con = sqlite3.connect(CRED_DB)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS credentials(
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id   TEXT UNIQUE,
            issuer          TEXT,
            subject         TEXT,
            issue_date      TEXT,
            expiration_date TEXT,
            iv              TEXT,
            cipher          TEXT,
            sig_issuer      TEXT,
            payload         TEXT
        )"""
    )
    cur.execute("PRAGMA table_info(credentials)")
    cols = {r[1] for r in cur.fetchall()}
    for col in ("iv", "cipher"):
        if col not in cols:
            cur.execute(f"ALTER TABLE credentials ADD COLUMN {col} TEXT")
    con.commit()
    con.close()

ensure_credentials_schema()

def log_interaction(frm: str, to: str, req_obj: dict, resp_obj: dict) -> None:
    con = sqlite3.connect(LOG_DB)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_from TEXT, actor_to TEXT,
            request TEXT,   response TEXT,
            created_at TEXT
        )"""
    )
    cur.execute(
        """INSERT INTO logs(actor_from,actor_to,request,response,created_at)
           VALUES (?,?,?,?,?)""",
        (
            frm,
            to,
            json.dumps(req_obj, sort_keys=True),
            json.dumps(resp_obj, sort_keys=True),
            datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    con.commit()
    con.close()


def store_credential(cred: dict, payload: dict) -> None:
    """Salva sul DB la credenziale comprensiva di iv e cipher."""
    con = sqlite3.connect(CRED_DB)
    cur = con.cursor()
    cur.execute(
        """INSERT OR REPLACE INTO credentials
          (credential_id,issuer,subject,issue_date,expiration_date,
           iv,cipher,sig_issuer,payload)
          VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            cred["credential_id"],
            cred["issuer"],
            cred["subject"],
            cred["issue_date"],
            cred["expiration_date"],
            cred["iv"],
            cred["cipher"],
            cred["sig_issuer"],
            json.dumps(payload),
        ),
    )
    con.commit()
    con.close()


# ----------------------------------------------------------------- /request
@app.post("/request")
def request_credential():
    data = request.get_json(force=True)
    student_id = data.get("student_id")
    wallet_sk = SK_MAP.get(student_id)
    if wallet_sk is None:
        return {"error": "unknown student_id"}, 400

    nonce = uuid.uuid4().hex
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    msg = f"{student_id}|{data['exam_name']}|{data['exam_date']}|{nonce}|{ts}".encode()
    sig = wallet_sk.sign(msg).hex()

    req_obj = {**data, "nonce": nonce, "timestamp": ts, "signature": sig}

    resp = requests.post(
        f"{ISSUER_URL}/issue",
        json=req_obj,
        cert=(WALLET_TLS_CERT, WALLET_TLS_KEY),
        verify=CA_CERT_PATH,
    )
    resp.raise_for_status()
    cred = resp.json()  # contiene iv, cipher, sig_issuer

    # -- verifica firma dell’Issuer -----------------------------------
    issig = cred["sig_issuer"]
    to_verify = {k: v for k, v in cred.items() if k != "sig_issuer"}
    ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ISSUER_PK_HEX)).verify(
        bytes.fromhex(issig), json.dumps(to_verify, sort_keys=True).encode()
    )

    # -- decifra payload ----------------------------------------------
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=cred["credential_id"].encode(), info=None
    )
    k_enc = hkdf.derive(MASTER_KEY)
    aes = AESGCM(k_enc)
    payload = json.loads(
        aes.decrypt(bytes.fromhex(cred["iv"]), bytes.fromhex(cred["cipher"]), None)
    )

    store_credential(cred, payload)
    log_interaction("wallet", "issuer", req_obj, cred)
    return jsonify(cred), 200


# ----------------------------------------------------------------- /present
@app.post("/present")
def present_credential():
    data = request.get_json(force=True)
    cred_id = data.get("credential_id")
    need = data.get("need", [])

    con = sqlite3.connect(CRED_DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM credentials WHERE credential_id=?", (cred_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return {"error": "Unknown credential_id"}, 404

    payload = json.loads(row["payload"])
    wallet_sk = SK_MAP[row["subject"]]

    cred_meta = {
        "issuer": row["issuer"],
        "subject": row["subject"],
        "issue_date": row["issue_date"],
        "expiration_date": row["expiration_date"],
        "credential_id": cred_id,
        "iv": row["iv"],
        "cipher": row["cipher"],
        "holder_pk": wallet_sk.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex(),
        "sig_issuer": row["sig_issuer"],
    }

    revealed = {
        attr: {
            "value": payload[attr],
            "salt": payload.get(f"salt_{attr}"),
            "comm": payload.get(f"comm_{attr}"),
        }
        for attr in need
        if attr in payload
    }

    pres = {
        "credential": cred_meta,
        "need": need,
        "revealed": revealed,
        "nonce": uuid.uuid4().hex,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    pres["sig_wallet"] = wallet_sk.sign(json.dumps(pres, sort_keys=True).encode()).hex()

    log_interaction("wallet", "verifier", data, pres)
    return jsonify(pres), 200

# -----------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
