# verifier/Dockerfile
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "main:app", "-b", "0.0.0.0:8000", "--workers", "3", \
     "--certfile", "/etc/ssl/certs/verifier.crt", \
     "--keyfile",  "/etc/ssl/private/verifier.key", \
     "--ca-certs", "/etc/ssl/certs/ca.crt", \
     "--cert-reqs", "2"]
