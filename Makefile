# 한 줄 명령 모음. 자세한 것은 CLAUDE.md 「명령」 절.
.PHONY: db test lint typecheck check dev-backend prod-local prod-local-down

db:  ## 로컬 시험·개발용 Postgres (127.0.0.1:15444, 프로젝트 sandcorp-auth-dev)
	docker compose up -d --wait db

test: db
	cd backend && uv run pytest

lint:
	cd backend && uv run ruff format --check . && uv run ruff check .

typecheck:
	cd backend && uv run mypy .

check: lint typecheck test

dev-backend: db  ## http://localhost:8000 
	cd backend && DJANGO_DEBUG=1 uv run python manage.py migrate --noinput
	cd backend && DJANGO_DEBUG=1 uv run python manage.py runserver 8000

# 운영 compose를 로컬에서 띄워 본다(.env 필요: cp .env.example .env 후 값 채우기, ALLOWED_HOSTS에 localhost 포함).
# deploy/deploy.sh와 같은 순서(빌드 → postgres → migrate → web)로 띄운다. http://127.0.0.1:18093
prod-local:
	COMPOSE_PROJECT_NAME=sandcorp-auth-local COMPOSE_FILE=docker-compose.prod.yml bash deploy/deploy.sh

prod-local-down:
	docker compose -p sandcorp-auth-local -f docker-compose.prod.yml down -v
