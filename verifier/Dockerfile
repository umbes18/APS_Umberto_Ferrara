# usa immagine Python multi-arch (supporta arm64 su M1)
FROM python:3.12-slim

# imposta la working dir
WORKDIR /app

# copia e installa dipendenze
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install merkletools --no-deps

# copia il codice dentro il container
COPY . .

# esponi la porta FastAPI interna
EXPOSE 8000

# comando di default
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
