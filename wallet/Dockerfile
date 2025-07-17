FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install merkletools --no-deps
COPY . .
# il wallet è un CLI, non serve exporre porte
CMD ["python", "main.py", "serve"]
