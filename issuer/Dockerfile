# ------------------------------------------------------------------------------
# Issuer – Flask + Gunicorn  (Ed25519, AES-GCM, Merkle-CRL)
# ------------------------------------------------------------------------------

FROM python:3.12-slim
WORKDIR /app

# per cryptography e TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# dipendenze
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# sorgenti
COPY . .

# esponi porta (mTLS su 8000)
EXPOSE 8000

CMD ["gunicorn", "issuer.main:app", "-b", "0.0.0.0:8000", "--workers", "4", \
     "--certfile", "/etc/ssl/certs/issuer.crt", \
     "--keyfile",  "/etc/ssl/private/issuer.key", \
     "--ca-certs", "/etc/ssl/certs/ca.crt", \
     "--cert-reqs", "2"]
