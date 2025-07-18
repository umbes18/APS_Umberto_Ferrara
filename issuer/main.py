import os
import json
import base64
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from markupsafe import Markup

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Configura directory per salvare le credenziali
DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)

# Generazione o caricamento della chiave privata dell'Issuer
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()


@app.route("/", methods=["GET"])
def dashboard():
    """
    Issuer Dashboard: lista delle credenziali emesse,
    con link per visualizzarle/scaricarle.
    """
    files = sorted(os.listdir(DATA_DIR))
    items = [
        f'<li><a href="/credentials/{fname}" target="_blank">{fname}</a></li>'
        for fname in files
    ]
    html = f"""
    <html>
      <head><title>Issuer Dashboard</title></head>
      <body>
        <h1>Issuer Dashboard</h1>
        <p>Credenziali emesse ({len(files)}):</p>
        <ul>
          {Markup(''.join(items))}
        </ul>
      </body>
    </html>
    """
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/credentials/<path:filename>", methods=["GET"])
def serve_credential(filename):
    """
    Serve un file JSON dalla cartella data/
    """
    return send_from_directory(DATA_DIR, filename, mimetype="application/json")


@app.route("/issue", methods=["POST"])
def issue_credential():
    """
    Endpoint per emettere una nuova credenziale:
    - Richiede JSON con 'subject' e 'claims'
    - Firma la credenziale
    - Salva il JSON in DATA_DIR
    - Restituisce la credenziale firmata
    """
    data = request.get_json(force=True)
    if not data or "subject" not in data or "claims" not in data:
        return jsonify({"error": "Bad Request, dati insufficienti"}), 400

    credential = {
        "issuer": "did:example:issuer-12345",
        "subject": data["subject"],
        "claims": data["claims"],
        "issued": datetime.utcnow().isoformat() + "Z"
    }

    # Serializza e firma
    cred_bytes = json.dumps(credential).encode("utf-8")
    signature = private_key.sign(
        cred_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    credential["signature"] = base64.b64encode(signature).decode("utf-8")

    # Salva su file
    safe_subject = credential["subject"].replace(":", "_")
    filename = f"{credential['issued']}--{safe_subject}.json"
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(credential, f, ensure_ascii=False, indent=2)

    return jsonify(credential), 200


@app.route("/issuer/pubkey", methods=["GET"])
def get_pubkey():
    """
    Endpoint per ottenere la chiave pubblica dell'Issuer
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({
        "issuer": "did:example:issuer-12345",
        "publicKeyPem": pem.decode("utf-8")
    }), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
