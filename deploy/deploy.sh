#!/usr/bin/env bash
# Called by Jenkins on the oracle agent from the job workspace, which holds ./.env (not in the repo).
#   1) get the image: AUTH_IMAGE set (Jenkins: ghcr.io/sandcorporation/sandcorp-auth:<sha>, built off-host, #68)
#      -> docker pull only, never build on oracle; AUTH_IMAGE unset (make prod-local) -> build locally
#   2) wait until the database answers  3) migrate in a one-off container
#   4) replace web      5) wait for the health check (it round-trips to the database)
# The database is OCI MySQL HeatWave (DB_* in .env), outside compose. `make prod-local` adds a local
# `mysql` service (docker-compose.prod-local.yml); it is started first when present.
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

if [ -n "${AUTH_IMAGE:-}" ]; then
  # ghcr 읽기 로그인은 oracle 호스트의 docker 설정에 있다. 빌드하지 않는다.
  echo "== 이미지 pull ($AUTH_IMAGE)"
  docker pull "$AUTH_IMAGE"
  BUILD_FLAG=--no-build
else
  echo "== 이미지 빌드"
  compose build web
  BUILD_FLAG=
fi

if compose config --services | grep -qx mysql; then
  echo "== 로컬 MySQL (prod-local 전용, 이미 떠 있으면 그대로)"
  compose up -d --no-recreate mysql
  wait_healthy mysql
fi

echo "== DB 접속 대기"
# MySQL DDL is not transactional: never start migrate against a database that is not answering.
compose run --rm --no-deps web sh -c '
  for i in $(seq 1 30); do
    python manage.py check --database default >/dev/null 2>&1 && { echo "DB 응답 (${i}회째)"; exit 0; }
    sleep 2
  done
  python manage.py check --database default'

echo "== migrate"
compose run --rm --no-deps web python manage.py migrate --noinput

echo "== web 교체"
# --force-recreate: 새로 빌드한 이미지라도 compose가 "Running"으로 두고 넘어가는 경우가 있었다.
compose up -d $BUILD_FLAG --no-deps --force-recreate web
wait_healthy web

echo "== 헬스 확인"
compose exec -T web python -c "
import os, urllib.request as u
host = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost').split(',')[0].strip()
print(u.urlopen(u.Request('http://127.0.0.1:8000/api/health', headers={'Host': host}), timeout=5).read().decode())
"
compose ps
docker image prune -f --filter label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-sandcorp-auth} >/dev/null || true
if [ -n "${AUTH_IMAGE:-}" ]; then
  # 최신 3개만 남긴다(되돌리기용). 쓰고 있는 이미지는 docker가 지우지 않는다.
  repo="${AUTH_IMAGE%:*}"
  docker images "$repo" --format '{{.Repository}}:{{.Tag}}' | tail -n +4 | xargs -r docker rmi >/dev/null 2>&1 || true
fi
