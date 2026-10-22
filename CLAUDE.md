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
- 인가 서버 핵심(OAuth 프로토콜 처리)은 authlib다. `backend/oauth/server.py`의 `server`에 엔드포인트·그랜트를 등록하고, 손으로 짜는 것은 authlib에 없는 부분(CIMD, RFC 8707 `resource`, 동의 화면)뿐이다.
- 스택과 명령은 `~/workspace/portfolio`와 같은 형태를 따른다: `backend/`(uv, Python 3.13, Django, django-ninja), `make test` / `make lint` / `make typecheck` / `make check`.
- 배포·운영(env 변수, 첫 배포, 관리 명령, 프록시, 백업)은 `docs/operations.md`. 운영 절차가 바뀌는 티켓은 그 문서도 함께 고친다.
- 두 사이트(portfolio, 뉴스)의 토큰 검증 규칙은 `docs/resource-server-token-validation.md`(참조 구현 `backend/tests/reference_validator.py`).

## 명령

저장소 루트에서 `make <대상>`. 백엔드는 `backend/`(uv, Python 3.13). 프론트엔드는 없다.

- 시험: `make test`. Postgres를 쓴다 — `make db`가 `sandcorp-auth-dev` 프로젝트로 `127.0.0.1:15444`에 띄운다(`make test`가 알아서 부른다).
- 린트: `make lint` (ruff format --check, ruff check). 고치기: `cd backend && uv run ruff format . && uv run ruff check --fix .`
- 타입: `make typecheck` (mypy strict + django-stubs).
- 전부: `make check` (= `lint typecheck test`).
- 작업자는 이 「명령」 절을 명령이 바뀌는 티켓에서 함께 고친다.
- 로컬 실행: `make dev-backend` (Django, :8000). authlib는 http로 온 OAuth 요청(`/authorize`·`/token`)을 막으므로, 로컬에서 http로 시험하려면 `AUTHLIB_INSECURE_TRANSPORT=1`을 켜고 띄운다. 시험에서는 `use_https(client)`, 토큰까지 한 번에 받으려면 `obtain_tokens(client, oauth_client)`·`exchange_code(...)`(`tests/conftest.py`).
- 시험에서 시각·난수: 서비스는 `adapters.clock.get_clock()`·`adapters.randomness.get_randomness()`로 받고, 시험은 `frozen_clock` 픽스처(`tests/conftest.py`)로 시각을 고정한다(`frozen_clock.advance(초)`).
- 서명 키: `cd backend && uv run python manage.py signing_keys create|rotate|list` (`create`는 활성 키가 없을 때만, 있으면 종료 코드 1. `rotate`는 새 활성 키를 만들고 이전 키는 10분 동안 JWKS에 남긴다). env `SIGNING_KEY_ENCRYPTION_KEY`(Fernet 키, 만드는 법은 `.env.example`)가 필요하다. 시험에서 활성 키가 필요하면 `signing_key` 픽스처, 난수를 들여다보려면 `recording_randomness` 픽스처.
- 대표 계정: `cd backend && uv run python manage.py owner create|set-password|reset-totp` (`create --username`은 기본 `farrar142`, 이 이름이 토큰 `sub`. 비밀번호는 `--password` 또는 프롬프트/표준 입력. 계정은 하나뿐이라 두 번째 `create`는 종료 코드 1. `reset-totp`는 장치를 지워 다음 로그인에 TOTP 등록을 강제). 시험에서는 `owner` 픽스처(등록 전 계정), `logged_in_client` 픽스처(비밀번호+TOTP 끝난 클라이언트), `tests.conftest.totp_code(user)`(고정 시계 기준 현재 코드).
- 기밀 클라이언트(사이트 관리 화면 로그인): `cd backend && uv run python manage.py clients create-confidential --name <이름> --redirect-uri <https URI> [--redirect-uri …]` → `client_id`·`client_secret`을 한 번만 출력(DB엔 해시). `clients rotate-secret --client-id <id>`(옛 시크릿 즉시 무효), `clients list`. admin 「클라이언트 추가」도 기밀 전용이다. 시험에서는 `portfolio_site_client`·`news_site_client` 픽스처(`tests/test_confidential_clients.py`, `(client, secret)`).
- 운영 compose 로컬 확인: `.env.example`을 `.env`로 복사해 값을 채우고(`DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1`, `SITE_URL`·`DJANGO_CSRF_TRUSTED_ORIGINS`=`http://127.0.0.1:18093`, `TRUST_X_FORWARDED_FOR=0`, OAuth 흐름까지 보려면 `AUTHLIB_INSECURE_TRANSPORT=1` — 로컬만) `make prod-local` → http://127.0.0.1:18093 . 관리 명령은 `docker compose -p sandcorp-auth-local -f docker-compose.prod.yml exec web python manage.py …`. 끝나면 `make prod-local-down`(볼륨 포함)과 `rm .env`. 자세한 것은 `docs/operations.md` 8절.
- 운영 서버의 관리 명령: `docker exec -it sandcorp-auth-web-1 python manage.py …`(`docs/operations.md` 0·3절).
- 운영 보안 설정(HSTS 1년·서브도메인 없음, `SECURE_SSL_REDIRECT` 끔, `X_FRAME_OPTIONS=DENY`, Referrer `same-origin`, 쿠키 Secure·Lax)은 `config/settings.py`. `check --deploy`에 남는 W005·W008·W021은 의도한 것이다(`docs/operations.md` 4절).
