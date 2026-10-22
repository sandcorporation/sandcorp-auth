#!/usr/bin/env bash
# Called by Jenkins on the oracle agent from the job workspace, which holds ./.env (not in the repo).
#   1) build the image  2) make sure postgres is up  3) migrate in a one-off container
#   4) replace web      5) wait for the health check (it round-trips to Postgres)
# Migrations run while the old web still serves, so destructive schema changes take two deploys.
set -euo pipefail

if [ ! -f .env ]; then
  echo "워크스페이스에 .env가 없다. .env.example을 보고 만들어 두어야 한다." >&2
  exit 1
fi

compose() { docker compose "$@"; }

wait_healthy() {
  local svc=$1
  for i in $(seq 1 60); do
    local id status
    id=$(compose ps -q "$svc")
    status=$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || echo starting)
    if [ "$status" = "healthy" ]; then
      echo "$svc healthy (${i}회째)"
      return 0
    fi
    sleep 2
  done
  echo "$svc가 healthy가 되지 않았다" >&2
  compose logs --tail 80 "$svc" >&2
  return 1
}

echo "== 이미지 빌드"
compose build web

echo "== Postgres (이미 떠 있으면 그대로)"
compose up -d --no-recreate postgres
wait_healthy postgres

echo "== migrate"
compose run --rm --no-deps web python manage.py migrate --noinput

echo "== web 교체"
# --force-recreate: 새로 빌드한 이미지라도 compose가 "Running"으로 두고 넘어가는 경우가 있었다.
compose up -d --no-deps --force-recreate web
wait_healthy web

echo "== 헬스 확인"
compose exec -T web python -c "
import os, urllib.request as u
host = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost').split(',')[0].strip()
print(u.urlopen(u.Request('http://127.0.0.1:8000/api/health', headers={'Host': host}), timeout=5).read().decode())
"
compose ps
docker image prune -f --filter label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-sandcorp-auth} >/dev/null || true
