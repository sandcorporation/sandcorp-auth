# sandcorp-auth

Sandcorp 사이트들(sandcorp.co.kr, news.sandcorp.co.kr)의 대표 로그인과 OAuth 2.1 인가를 맡는 독립 인증 서비스. auth.sandcorp.co.kr.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues (`sandcorporation/sandcorp-auth`, via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage labels are used as-is: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## 작업 흐름

- 스펙은 #1, 티켓은 그 하위 이슈다. 이슈마다 워크트리 `~/workspace/sandcorp-auth-wt/<브랜치>`에서 작업하고 `origin/main`으로 PR을 연다.
- PR CI는 없다. 시험·린트·타입 검사는 로컬에서 돌린다. 통과하면 작업자가 바로 squash 병합한다(main 직접 push 금지).
- 배포와 서버 설정(env 파일, NPMplus, DNS, OCI)은 조율자가 다룬다. 작업자는 원격 호스트에 쓰지 않는다.
- 스택과 명령은 `~/workspace/portfolio`와 같은 형태를 따른다: `backend/`(uv, Python 3.13, Django, django-ninja), `make test` / `make lint` / `make typecheck` / `make check`.
- 두 사이트(portfolio, 뉴스)의 토큰 검증 규칙은 `docs/resource-server-token-validation.md`(참조 구현 `backend/tests/reference_validator.py`).

## 명령

저장소 루트에서 `make <대상>`. 백엔드는 `backend/`(uv, Python 3.13). 프론트엔드는 없다.

- 시험: `make test`. Postgres를 쓴다 — `make db`가 `sandcorp-auth-dev` 프로젝트로 `127.0.0.1:15444`에 띄운다(`make test`가 알아서 부른다).
- 린트: `make lint` (ruff format --check, ruff check). 고치기: `cd backend && uv run ruff format . && uv run ruff check --fix .`
- 타입: `make typecheck` (mypy strict + django-stubs).
- 전부: `make check` (= `lint typecheck test`).
- 작업자는 이 「명령」 절을 명령이 바뀌는 티켓에서 함께 고친다.
- 로컬 실행: `make dev-backend` (Django, :8000).
- 시험에서 시각·난수: 서비스는 `adapters.clock.get_clock()`·`adapters.randomness.get_randomness()`로 받고, 시험은 `frozen_clock` 픽스처(`tests/conftest.py`)로 시각을 고정한다(`frozen_clock.advance(초)`).
- 서명 키: `cd backend && uv run python manage.py signing_keys create|rotate|list` (`create`는 활성 키가 없을 때만, 있으면 종료 코드 1. `rotate`는 새 활성 키를 만들고 이전 키는 10분 동안 JWKS에 남긴다). env `SIGNING_KEY_ENCRYPTION_KEY`(Fernet 키, 만드는 법은 `.env.example`)가 필요하다. 시험에서 활성 키가 필요하면 `signing_key` 픽스처, 난수를 들여다보려면 `recording_randomness` 픽스처.
- 운영 compose 로컬 확인: `.env.example`을 `.env`로 복사해 값을 채우고(`DJANGO_ALLOWED_HOSTS`에 `localhost`) `COMPOSE_PROJECT_NAME=sandcorp-auth-local COMPOSE_FILE=docker-compose.prod.yml bash deploy/deploy.sh` → http://127.0.0.1:18093 . 끝나면 `make prod-local-down`.
