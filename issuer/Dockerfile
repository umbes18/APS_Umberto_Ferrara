FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY templates ./templates
EXPOSE 8000

# In WP2 il servizio va avviato in modalità WSGI,
# Gunicorn ti dà subito multi-worker e configurazioni di produzione.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "main:app", "--workers", "4"]
