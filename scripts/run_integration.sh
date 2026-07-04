#!/usr/bin/env bash

set -euo pipefail

export POSTGRES_USER="${POSTGRES_USER:-postgres}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}"
export POSTGRES_DB="${POSTGRES_DB:-security_scanner}"
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://postgres:postgres@db:5432/security_scanner}"
export SECRET_KEY="${SECRET_KEY:-ci-only-secret-change-in-production}"
export ACCESS_TOKEN_EXPIRE_MINUTES="${ACCESS_TOKEN_EXPIRE_MINUTES:-30}"

COMPOSE_FILES=(-f docker/docker-compose.yml -f docker-compose.ci.yml)

cleanup() {
  docker compose "${COMPOSE_FILES[@]}" logs --no-color > docker-compose.integration.log || true
  docker compose "${COMPOSE_FILES[@]}" down -v || true
}

trap cleanup EXIT

docker compose "${COMPOSE_FILES[@]}" up -d --build app db target-site

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}" \
TARGET_SCAN_URL="${TARGET_SCAN_URL:-http://target-site}" \
pytest -q -m integration
