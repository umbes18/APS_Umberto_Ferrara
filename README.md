# APS_Umberto_Ferrara — WP4

**Componenti**  
- Issuer (FastAPI) → `http://localhost:8001/docs`  
- Verifier (FastAPI) → `http://localhost:8002/docs`  
- Wallet (CLI) → `docker-compose run --rm wallet python main.py <comando>`

## Setup

```bash
# 1. Clona il repo
git clone https://github.com/umbes18/APS_Umberto_Ferrara.git
cd APS_Umberto_Ferrara

# 2. Avvia via Docker Compose
docker-compose up --build -d
docker-compose down

