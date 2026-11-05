#!/usr/bin/env bash
# Build and start SQL Server + ML + API + Web locally.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "Create Deployment/.env first (cp .env.example .env; scripts/generate_secrets.sh)"; exit 1; }
[ -f ../ML/models/zero_day_bundle.joblib ] || { echo "Train the model first: cd ML && python train_model.py --dataset cicids2017"; exit 1; }
docker compose up --build -d
echo "Web: http://localhost:5000   API: http://localhost:5001/swagger   ML: http://localhost:8000/health"
