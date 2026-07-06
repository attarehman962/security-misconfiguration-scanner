#!/usr/bin/env bash

set -Eeuo pipefail

export POSTGRES_USER="${POSTGRES_USER:-postgres}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}"
export POSTGRES_DB="${POSTGRES_DB:-security_scanner}"
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://postgres:postgres@db:5432/security_scanner}"
export SECRET_KEY="${SECRET_KEY:-ci-only-secret-change-in-production}"
export ACCESS_TOKEN_EXPIRE_MINUTES="${ACCESS_TOKEN_EXPIRE_MINUTES:-30}"
export APP_PORT="${APP_PORT:-8000}"
export BASE_URL="${BASE_URL:-http://127.0.0.1:${APP_PORT}}"
export TARGET_SCAN_URL="${TARGET_SCAN_URL:-http://target-site}"
export SKIP_DOCKER_BUILD="${SKIP_DOCKER_BUILD:-false}"

COMPOSE_FILES=(-f docker/docker-compose.yml -f docker/docker-compose.ci.yml)
INTEGRATION_LOG_FILE="${INTEGRATION_LOG_FILE:-docker-compose.integration.log}"
LOG_TAIL_LINES="${LOG_TAIL_LINES:-300}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-90}"

compose() {
  docker compose "${COMPOSE_FILES[@]}" "$@"
}

save_logs() {
  compose logs --no-color > "${INTEGRATION_LOG_FILE}" || true
}

print_diagnostics() {
  echo "Integration run failed. Recent Docker Compose status and logs:" >&2
  compose ps >&2 || true
  compose logs --no-color --tail="${LOG_TAIL_LINES}" >&2 || true
  echo "Full Docker Compose log saved to ${INTEGRATION_LOG_FILE}" >&2
}

cleanup() {
  save_logs
  compose down -v || true
}

wait_for_service() {
  local service="$1"
  local deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))
  local container_id=""
  local state=""
  local health=""

  while ((SECONDS < deadline)); do
    container_id="$(compose ps -q "${service}" 2>/dev/null || true)"

    if [[ -n "${container_id}" ]]; then
      read -r state health <<< "$(
        docker inspect \
          --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
          "${container_id}" 2>/dev/null || echo "missing missing"
      )"

      if [[ "${health}" == "healthy" || ("${health}" == "none" && "${state}" == "running") ]]; then
        echo "${service} is ready (${state}/${health})."
        return 0
      fi

      if [[ "${state}" == "exited" || "${state}" == "dead" || "${health}" == "unhealthy" ]]; then
        echo "${service} failed while waiting for readiness (${state}/${health})." >&2
        docker inspect "${container_id}" >&2 || true
        return 1
      fi
    fi

    sleep 2
  done

  echo "${service} did not become ready within ${WAIT_TIMEOUT_SECONDS}s." >&2
  return 1
}

wait_for_target_site() {
  local deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))

  while ((SECONDS < deadline)); do
    if compose exec -T target-site wget -q -O /dev/null http://127.0.0.1/; then
      echo "target-site is ready."
      return 0
    fi

    sleep 2
  done

  echo "target-site did not serve HTTP within ${WAIT_TIMEOUT_SECONDS}s." >&2
  return 1
}

run_integration() {
  if [[ "${SKIP_DOCKER_BUILD}" == "true" ]]; then
    compose up -d app db target-site || return
  else
    compose up -d --build app db target-site || return
  fi

  wait_for_service db || return
  wait_for_service app || return
  wait_for_target_site || return
  pytest -q -m integration
}

trap cleanup EXIT

if ! run_integration; then
  save_logs
  print_diagnostics
  exit 1
fi
