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
- 두 사이트(portfolio, 뉴스)의 토큰 검증 규칙은 `docs/resource-server-token-validation.md`(참조 구현 `backend/tests/reference_validator.py`). 일반 사용자를 받는 사이트는 그 문서 10절.

## 명령

저장소 루트에서 `make <대상>`. 백엔드는 `backend/`(uv, Python 3.13). 프론트엔드는 없다.

- 시험: `make test`. MySQL을 쓴다 — `make db`가 `mysql:26.10.0`(`utf8mb4_0900_as_cs`)을 `sandcorp-auth-dev` 프로젝트로 `127.0.0.1:15444`에 띄운다(`make test`가 알아서 부른다; 13306은 쓰지 않는다). 시험 설정 `config.test_settings`가 `DB_PORT=15444`를 기본으로 두고, 시험 DB `test_sandcorp_auth`도 as_cs로 만든다. 전체 약 3분 40초(비밀번호 해시가 대부분).
- DB(ADR 0002, #30): MySQL 단일 백엔드, 드라이버 `mysqlclient`. 접속은 env `DB_HOST`·`DB_PORT`(기본 3306)·`DB_NAME`·`DB_USER`·`DB_PASSWORD`. 격리 수준은 Django 기본(READ COMMITTED) 그대로 둔다. MySQL에 없는 것 두 가지: 부분 유일 인덱스(「조건이 참인 행은 하나」는 `oauth/models.py`의 `_live_marker` 생성 칼럼 + 일반 유일 제약), 교착 없는 `INSERT IGNORE` 후 잠금(「없으면 넣고 잠근다」는 `bulk_create(update_conflicts=True, update_fields=[...])` upsert, `services/throttle.py`). 이런 코드를 더하면 `tests/test_concurrency.py`(스레드 8개·실제 연결, `transaction=True, serialized_rollback=True`)에 탐침을 더한다. `client_id`는 `ascii_bin` 칼럼이라 ASCII가 아닌 값은 DB에 묻기 전에 거른다(`find_client`, admin 검색은 `oauth/admin.py`의 `_ascii_safe`). 운영 데이터 이전 절차는 `docs/ops/db-migration.md`.
- 디자인(#38): 화면은 sandcorp-design(`sc-` 접두 클래스, 토큰 `--color-*`)을 쓴다. `make sync-design VERSION=v0.3.1`이 dist CSS를 `backend/static/design/sandcorp.css`로 복사한다(커밋 대상, whitenoise가 `/static/design/sandcorp.css`로 내보낸다). 앱 CSS(`static/auth.css`)에는 원시 색을 쓰지 않고 토큰만 쓴다.
- 린트: `make lint` (ruff format --check, ruff check). 고치기: `cd backend && uv run ruff format . && uv run ruff check --fix .`
- 타입: `make typecheck` (mypy strict + django-stubs).
- 전부: `make check` (= `lint typecheck test`).
- 작업자는 이 「명령」 절을 명령이 바뀌는 티켓에서 함께 고친다.
- 로컬 실행: `make dev-backend` (Django, :8000). authlib는 http로 온 OAuth 요청(`/authorize`·`/token`)을 막으므로, 로컬에서 http로 시험하려면 `AUTHLIB_INSECURE_TRANSPORT=1`을 켜고 띄운다. 시험에서는 `use_https(client)`, 토큰까지 한 번에 받으려면 `obtain_tokens(client, oauth_client)`·`exchange_code(...)`(`tests/conftest.py`).
- 시험에서 시각·난수: 서비스는 `adapters.clock.get_clock()`·`adapters.randomness.get_randomness()`로 받고, 시험은 `frozen_clock` 픽스처(`tests/conftest.py`)로 시각을 고정한다(`frozen_clock.advance(초)`).
- 서명 키: `cd backend && uv run python manage.py signing_keys create|rotate|list` (`create`는 활성 키가 없을 때만, 있으면 종료 코드 1. `rotate`는 새 활성 키를 만들고 이전 키는 10분 동안 JWKS에 남긴다). env `SIGNING_KEY_ENCRYPTION_KEY`(Fernet 키, 만드는 법은 `.env.example`)가 필요하다. 시험에서 활성 키가 필요하면 `signing_key` 픽스처, 난수를 들여다보려면 `recording_randomness` 픽스처.
- 대표 계정: `cd backend && uv run python manage.py owner create|set-password|reset-totp|set-email --email <주소>|set-name --name <이름>` (`create --username`은 기본 `farrar142`, 이 이름이 토큰 `sub`. 비밀번호는 `--password` 또는 프롬프트/표준 입력. 계정은 하나뿐이라 두 번째 `create`는 종료 코드 1. `reset-totp`는 장치를 지워 다음 로그인에 TOTP 등록을 강제). 시험에서는 `owner` 픽스처(등록 전 계정), `logged_in_client` 픽스처(비밀번호+TOTP 끝난 클라이언트), `tests.conftest.totp_code(user)`(고정 시계 기준 현재 코드).
- 기밀 클라이언트(사이트 관리 화면 로그인): `cd backend && uv run python manage.py clients create-confidential --name <이름> --redirect-uri <https URI> [--redirect-uri …]` → `client_id`·`client_secret`을 한 번만 출력(DB엔 해시). `clients rotate-secret --client-id <id>`(옛 시크릿 즉시 무효), `clients list`. admin 「클라이언트 추가」도 기밀 전용이다. 시험에서는 `portfolio_site_client`·`news_site_client` 픽스처(`tests/test_confidential_clients.py`, `(client, secret)`).
- 일반 사용자(#35, ADR 0003): 계정은 대표 + 일반 사용자(member). member는 Django `User` + `accounts.Member`(+ `accounts.ExternalIdentity`, (provider, provider_sub) 유일), username = `sub` = `m_` + ULID, 비밀번호·TOTP·staff 없음. 규칙은 `services/members.py`(`create_member`·`account_kind`·`check_member_grant`·`MEMBER_SCOPES`=login·openid·profile·email). `Client.allows_members`(기본 꺼짐)가 켜진 클라이언트만 member에게 코드·토큰을 준다 — `/authorize`(꺼짐 `access_denied`, 금지 스코프 `invalid_scope`), `/token`(`invalid_grant`), 토큰 생성기 세 곳에서 본다. member 토큰·ID 토큰·userinfo에 `acct=member`, **대표 토큰엔 `acct` 없음**(기존 사이트 그대로). 사이트 규칙은 `docs/resource-server-token-validation.md` 10절, 참조 `validate_account_access_token`. 켜고 끄기: `clients members --client-id <id> --allow|--deny`, `create-confidential --allow-members`, admin. 시험은 `make_member()`·`member`·`member_client` 픽스처(`tests/conftest.py`), `tests/test_members.py`. 상태는 「동의 대기」(`Member.Status.PENDING_TERMS`, 만들 때)·「활성」(약관 동의로, #37).
- 소셜 로그인(#36): 제공자는 `services/social_providers.py`(`SocialProvider` Protocol, `GoogleProvider` — id_token 서명·aud·iss·exp·nonce를 `get_clock()`으로 검사, `KakaoProvider` — `/v2/user/me`, provider_sub = 회원번호 문자열), HTTP는 `adapters/social_http.py`(`get_provider_http`/`set_provider_http`). 흐름 규칙(state·PKCE·nonce 세션 10분 1회, 같은 이메일 안내, 연결·해제)은 `services/social.py`, 화면은 `accounts/social_views.py`(`/login/<provider>`, `/login/<provider>/callback`, `/signup/confirm`, `/account/identities`(+`/link/<provider>`·`/<id>/unlink`), 최소 템플릿). 소셜 버튼은 `next`가 `allows_members` 클라이언트의 `/authorize`일 때만이고 env `GOOGLE_CLIENT_ID`·`GOOGLE_CLIENT_SECRET`·`KAKAO_CLIENT_ID`·`KAKAO_CLIENT_SECRET` 중 그 제공자 값이 비면 숨는다(콘솔 절차 `docs/operations.md` 9절; Google은 구현됐으나 보류라 운영 env가 비어 꺼져 있다). 콜백 실패는 IP 규칙 `login`에 센다. 시험은 autouse `fake_providers`(`tests/conftest.py`, 시험 RSA 키로 id_token 서명; `google_codes[code] = claims`, `kakao_codes[code] = user`)와 `tests/test_social_login.py`의 `start`·`callback`·`google_login`·`kakao_login`.
- 약관 동의(#37): 문서 버전 `accounts.TermsDocument`(종류 `terms`·`privacy`, 버전·시행일·URL — 본문은 `sandcorporation/privacy-and-terms`, 주소만), 동의 `accounts.TermsAgreement`(사용자·버전·시각·만 14세 확인). 규칙은 `services/terms.py`(`current_documents`=종류마다 시행일 지난 최신, `needs_terms`, `agree_to_terms`, `register_document`; `TermsError` 계열). `check_member_grant`가 마지막에 `needs_terms`면 `MemberTermsPending` — `/authorize`는 동의 화면 `/terms?next=`로 돌리고(`oauth/views.authorize`), `/token`(코드·리프레시)은 `invalid_grant`, 토큰 생성기는 `RuntimeError`. 로그인 끝(`social_views._sign_into`)도 `/terms`로 보낸다. 화면 `accounts/terms_views.py` + 최소 템플릿 `terms.html`(필드 `document`(문서 id 여러 개)·`age_14`·`next`). 등록은 `manage.py terms add --kind … --doc-version … --effective YYYY-MM-DD --url …`·`terms list` 또는 admin(등록 뒤 수정·삭제 불가). 시행 중인 버전이 없는 종류가 있으면 가입이 막힌다(`docs/operations.md` 10절). 시험의 `make_member()`는 기본으로 첫 버전(`ensure_terms_documents()`)에 동의한 「활성」이고 `agreed=False`면 「동의 대기」, `tests/test_terms.py`.
- OIDC(#28, ADR 0001): discovery `/.well-known/openid-configuration`(RFC 8414 문서와 같은 함수 `oauth.server.authorization_server_metadata`), 로그인 정보 스코프·ID 토큰·userinfo 클레임·`/userinfo` 토큰 검증은 `services/oidc.py`. `resource` 없이 `openid`면 내부 리소스 `USERINFO_RESOURCE`(마이그레이션 0007)가 `aud`. 시험은 `tests/test_oidc.py`(`proxy` 픽스처 = 기밀 클라이언트).
- 운영 compose 로컬 확인: `.env.example`을 `.env`로 복사해 값을 채우고(`DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1`, `SITE_URL`·`DJANGO_CSRF_TRUSTED_ORIGINS`=`http://127.0.0.1:18093`, `TRUST_X_FORWARDED_FOR=0`, OAuth 흐름까지 보려면 `AUTHLIB_INSECURE_TRANSPORT=1` — 로컬만) `make prod-local`(DB는 `docker-compose.prod-local.yml`의 로컬 MySQL) → http://127.0.0.1:18093 . 관리 명령은 `docker compose -p sandcorp-auth-local -f docker-compose.prod.yml exec web python manage.py …`. 끝나면 `make prod-local-down`(볼륨 포함)과 `rm .env`. 자세한 것은 `docs/operations.md` 8절.
- 운영 서버의 관리 명령: `docker exec -it sandcorp-auth-web-1 python manage.py …`(`docs/operations.md` 0·3절).
- 운영 보안 설정(HSTS 1년·서브도메인 없음, `SECURE_SSL_REDIRECT` 끔, `X_FRAME_OPTIONS=DENY`, Referrer `same-origin`, 쿠키 Secure·Lax)은 `config/settings.py`. `check --deploy`에 남는 W005·W008·W021은 의도한 것이다(`docs/operations.md` 4절).
