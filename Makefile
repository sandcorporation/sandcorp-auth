# 한 줄 명령 모음. 자세한 것은 CLAUDE.md 「명령」 절.
.PHONY: db test lint typecheck check authkit-test authkit-lint authkit-typecheck dev-backend prod-local prod-local-down sync-design

db:  ## 로컬 시험·개발용 MySQL 26.10 (127.0.0.1:15444, 프로젝트 sandcorp-auth-dev)
	docker compose up -d --wait db

TEST_CPU_LIMIT ?= 1.0
export TEST_CPU_LIMIT

test: db authkit-test
	cd backend && uv run pytest

lint: authkit-lint
	cd backend && uv run ruff format --check . && uv run ruff check .

typecheck: authkit-typecheck
	cd backend && uv run mypy .

# 자원 서버 공용 패키지 sandcorp-authkit(clients/python, #54). DB가 필요 없다.
authkit-test:
	cd clients/python && uv run pytest

authkit-lint:
	cd clients/python && uv run ruff format --check . && uv run ruff check .

authkit-typecheck:
	cd clients/python && uv run mypy

check: lint typecheck test

dev-backend: db  ## http://localhost:8000 
	cd backend && DB_PORT=15444 DJANGO_DEBUG=1 uv run python manage.py migrate --noinput
	cd backend && DB_PORT=15444 DJANGO_DEBUG=1 uv run python manage.py runserver 8000

# sandcorp-design dist CSS를 받아 backend/static/design/sandcorp.css로 복사한다(커밋 대상). 예: make sync-design VERSION=v0.3.2
sync-design:
	@test -n "$(VERSION)" || { echo "VERSION=vX.Y.Z 필요"; exit 1; }
	mkdir -p backend/static/design
	curl -fsSL https://raw.githubusercontent.com/sandcorporation/sandcorp-design/$(VERSION)/dist/sandcorp.css -o backend/static/design/sandcorp.css
	echo "$(VERSION)" > backend/static/design/VERSION

# 운영 compose를 로컬에서 띄워 본다(.env 필요: cp .env.example .env 후 값 채우기, ALLOWED_HOSTS에 localhost 포함).
# deploy/deploy.sh와 같은 순서(빌드 → DB 대기 → migrate → web)로 띄운다. DB는 docker-compose.prod-local.yml의
# 로컬 MySQL(운영은 OCI HeatWave). http://127.0.0.1:18093
prod-local:
	COMPOSE_PROJECT_NAME=sandcorp-auth-local COMPOSE_FILE=docker-compose.prod.yml:docker-compose.prod-local.yml bash deploy/deploy.sh

prod-local-down:
	docker compose -p sandcorp-auth-local -f docker-compose.prod.yml -f docker-compose.prod-local.yml down -v
