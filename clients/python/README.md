# sandcorp-authkit

Sandcorp 자원 서버(portfolio, metrics, news, flow)가 auth.sandcorp.co.kr의 액세스 토큰을 검증하고, RFC 9728 메타데이터·`WWW-Authenticate`를 내고, Django·ninja에서 bearer 인증을 걸고, 관리 화면 운영자 로그인을 도는 공용 패키지. 규칙의 원문은 이 저장소 `docs/resource-server-token-validation.md`이고, 스펙은 sandcorp-auth #54.

- Python 3.14 이상, 의존성은 `pyjwt[crypto]`뿐. `sandcorp_authkit.django`만 extras `[django]`(Django ≥6.1, django-ninja ≥1.7)가 필요하다. `tokens`·`resource`·`login`·`testing`은 Django 없이 import된다(`tests/test_testing.py`가 깨끗한 인터프리터에서 확인).
- 설정은 함수 인자로만 받는다. 패키지는 settings·환경 변수를 읽지 않는다 — 저장소는 어댑터 한 파일에서 값을 넘긴다.

## 설치

```toml
# pyproject.toml
[project]
dependencies = ["sandcorp-authkit[django]"]

[tool.uv.sources]
sandcorp-authkit = { git = "ssh://git@github.com/sandcorporation/sandcorp-auth.git", subdirectory = "clients/python", tag = "authkit-v0.2.0" }
```

또는 `uv add "sandcorp-authkit[django] @ git+ssh://git@github.com/sandcorporation/sandcorp-auth.git@authkit-v0.2.0#subdirectory=clients/python"`. 태그를 고정하고, 올릴 때는 저장소마다 PR 하나.

저장소가 private이라 주소는 ssh다. Docker 빌드는 BuildKit SSH 전달(`RUN --mount=type=ssh`)로 키를 받고 키는 이미지에 남지 않는다. Jenkins/oracle 변형과 GitHub Actions 변형은 [`docs/resource-servers.md`](../../docs/resource-servers.md) 3절.

## 공개 API

### `sandcorp_authkit.tokens`

| 이름 | 무엇 |
|---|---|
| `validate_access_token(token, *, issuer, audience, required_scope, jwks, clock, extra_claims_hook=None) -> AccessToken` | 문서 3절 T1–T10 → 훅 → S1. 실패는 `TokenRejected`(401 `invalid_token`), 스코프 부족은 `InsufficientScope`(403) |
| `AccessToken` | `sub`, `client_id`, `scopes`(frozenset), `jti`, `iat`, `exp`, `acct`(문자열이면 그 값, 아니면 None) |
| `TokenRejected`, `InsufficientScope(required_scope)` | 예외. 메시지는 서버 로그용 — 응답에 싣지 않는다 |
| `JwksCache(fetch_jwks, clock, *, ttl_seconds=600, min_refetch_seconds=60)` | 4절 J1–J5. 스레드 안전. 프로세스마다 하나 |
| `http_jwks_fetcher(url, *, timeout=5.0, max_bytes=65536)` | 표준 라이브러리 `urllib`로 JWKS를 받는 `fetch_jwks` |
| `Clock`(Protocol, `now() -> aware datetime`), `SystemClock` | 시각 주입 |
| `owner_only(owner_sub)`, `owner_or_member(owner_sub)` | `extra_claims_hook`으로 넘기는 계정 규칙. 대표만 받는 사이트는 앞의 것(T11), 일반 사용자도 받는 사이트(flow)는 뒤의 것(10절 A1–A3) |
| `ClaimsHook`, `JwksFetcher` | 타입 별칭 |
| 상수 `ALGORITHM`, `REQUIRED_CLAIMS`, `EXP_LEEWAY_SECONDS`, `JWKS_TTL_SECONDS`, `JWKS_MIN_REFETCH_SECONDS`, `MEMBER_SUB`, `ACCOUNT_KIND_CLAIM` | |

```python
from sandcorp_authkit.tokens import (
    JwksCache,
    SystemClock,
    http_jwks_fetcher,
    owner_only,
    validate_access_token,
)

clock = SystemClock()
jwks = JwksCache(http_jwks_fetcher("https://auth.sandcorp.co.kr/.well-known/jwks.json"), clock)
token = validate_access_token(
    raw,
    issuer="https://auth.sandcorp.co.kr",
    audience="https://sandcorp.co.kr/mcp",
    required_scope="admin",
    jwks=jwks,
    clock=clock,
    extra_claims_hook=owner_only("farrar142"),
)
```

### `sandcorp_authkit.resource`

| 이름 | 무엇 |
|---|---|
| `protected_resource_metadata(resource, authorization_server, scopes_supported, *, resource_name=None)` | 6절 JSON 본문(dict). `bearer_methods_supported`는 `["header"]` 고정 |
| `metadata_path(resource)` | RFC 9728 3.1절: `https://x/mcp` → `/.well-known/oauth-protected-resource/mcp`, 경로 없으면 `/.well-known/oauth-protected-resource`. 쿼리·프래그먼트가 있는 자원은 `ValueError` |
| `metadata_url(resource)` | 자원 원점 + `metadata_path` |
| `www_authenticate(resource_metadata_url, *, error=None, scope=None)` | 5절 문자열 그대로. 401은 `Bearer resource_metadata="…"`(+ `, error="invalid_token"`), 403은 `Bearer error="insufficient_scope", scope="…"` |

### `sandcorp_authkit.django` (extras `[django]`)

| 이름 | 무엇 |
|---|---|
| `BearerConfig(issuer, audience, resource_metadata_url, jwks, clock, extra_claims_hook=None)` | 검증 설정. 값 그대로 넘기거나 **인자 없는 함수**로 넘긴다(요청마다 부르므로 시험의 `settings` 바꾸기가 먹는다). 함수가 `AuthNotConfigured`를 던져도 된다 |
| `require_bearer(scope, *, config)` | Django 뷰 데코레이터. 뷰는 `view(request, token, *args, **kwargs)`, `request.access_token`에도 같은 `AccessToken` |
| `BearerAuth(scope, *, config)` | django-ninja `auth=`. `request.auth`가 `AccessToken`. 거부는 `BearerDenied`(완성된 응답을 싣는다) |
| `install_bearer_errors(api)` | NinjaAPI마다 한 번. `BearerDenied`를 그 응답으로 돌려준다(없으면 ninja가 500) |
| `authenticate(request, scope, config) -> AccessToken` | 검사 자체. 설정 → 헤더 → 3절 순서. `AuthNotConfigured`·`MissingToken`·`TokenRejected`·`InsufficientScope`를 그대로 던진다(MCP 뷰처럼 직접 쓰는 곳용) |
| `deny(request, error, *, resource_metadata_url, scope=None) -> HttpResponse` | 위 네 예외의 응답(아래 표) |
| `bearer_token(request)` | `Authorization: Bearer <토큰>`의 토큰. 없으면 `MissingToken` |
| `metadata_response(resource, authorization_server, scopes_supported, *, resource_name=None)` | 6절 메타데이터 `JsonResponse` + `Access-Control-Allow-Origin: *` |
| `AuthNotConfigured`, `MissingToken`, `BearerDenied(error, response)` | 예외 |

| 경우 | 상태 | `WWW-Authenticate` | 본문 |
|---|---|---|---|
| 설정 빔(`AuthNotConfigured`) — 헤더를 보기 전 | 503 | 없음 | `{"error": "auth_not_configured"}` |
| 토큰 없음·다른 스킴·`Bearer ` 뒤가 빔 | 401 | `Bearer resource_metadata="…"` | `{"error": "unauthorized"}` |
| 토큰 거부 | 401 | `Bearer resource_metadata="…", error="invalid_token"` | `{"error": "unauthorized"}` |
| 스코프 부족 | 403 | `Bearer error="insufficient_scope", scope="…"` | `{"error": "forbidden"}` |

### `sandcorp_authkit.login`

| 이름 | 무엇 |
|---|---|
| `LoginConfig(client_id, client_secret, redirect_uri, authorize_url, token_url, issuer, resource, scope="login")` | 기밀 클라이언트 등록값. `complete`(전부 채워졌나), `wants_id_token`(`scope`에 `openid`) |
| `start_login(config, store, *, clock, extra=None) -> str` | state(32B)·`code_verifier`(64B → 86자)·nonce(32B)를 만들어 `store`에 두고 `/authorize` URL을 돌려준다. 설정이 비면 `LoginRejected("config")` |
| `complete_login(query, config, store, *, jwks, clock, required_scope="login", extra_claims_hook=None, transport=None) -> LoginResult` | 콜백 검증 끝까지. 실패는 `LoginRejected(reason)` |
| `LoginResult` | `access`(`AccessToken`), `identity`(`IdentityClaims` 또는 None), `extra`(`start_login`이 실어 보낸 값) |
| `LoginRejected.reason` | `config`·`state`·`expired`·`denied`·`exchange`·`token`. 로그와 화면 고르기용 — URL에 싣지 않는다 |
| `AttemptStore`(Protocol: `save(attempt)`, `take() -> LoginAttempt | None`), `SessionAttemptStore(session, key="sandcorp_authkit.login")` | 시도 저장소. Django `request.session`을 그대로 넘긴다. 한 칸이고 `take`는 꺼내면서 지운다 |
| `LoginAttempt(state, code_verifier, nonce, started_at, extra)`, `to_dict()`/`from_dict()` | 시도 한 번. `from_dict`는 모양이 다르면 None |
| `exchange_code(config, *, code, code_verifier, transport=None, timeout=5.0, max_bytes=65536) -> TokenResponse` | `POST /token`, client_secret_basic. 실패는 `TokenExchangeFailed` |
| `TokenTransport` = `Callable[[TokenRequest], TransportResponse]`, `urllib_transport`, `TokenRequest`, `TransportResponse` | 전송 함수 자리. 기본은 urllib(리다이렉트 안 따름). 시험은 `testing.FakeTokenEndpoint` |
| `verify_id_token(id_token, *, issuer, client_id, nonce, access, jwks, clock) -> IdentityClaims` | 10절. 실패는 `IdTokenRejected` |
| `code_challenge(verifier)` | S256 |
| 상수 `ATTEMPT_MAX_AGE_SECONDS`(600), `TOKEN_TIMEOUT_SECONDS`(5), `TOKEN_MAX_BYTES`(65536), `LOGIN_SCOPE` | |

`complete_login` 순서: 설정 → 시도 꺼냄(뒤가 실패해도 이미 지워짐) → `state` 비교(상수 시간) → 시도 나이 ≤ 600초 → `error` 파라미터 → `code` → 교환 → 액세스 토큰 3절(`aud`=`config.resource`, `required_scope`, 훅) + `client_id`가 이 클라이언트 → ID 토큰(`openid`를 요청했으면 필수, 요청 안 했어도 왔으면 검증). 대표/일반 사용자 진입 구분, `admin` 스코프 요구 같은 것은 사이트가 `LoginResult.access`로 본다.

### `sandcorp_authkit.testing`

| 이름 | 무엇 |
|---|---|
| `FixedClock(moment=2026-01-01 UTC)`, `.now()`, `.advance(초)` | `Clock` 구현(aware datetime만) |
| `SigningKey(kid="test-key")`, `.jwk()`, `.sign(claims, *, headers=None)` | Ed25519 키. `headers`를 주면 헤더 전체를 바꾼다(kid 빼기·바꾸기) |
| `FakeJwks(*keys)` | JWKS 엔드포인트(`JwksFetcher`). `document`, `fetches`, `failing`(→ `OSError`), `key`(서명 키), `serve(*keys)`, `rotate(kid)`(옛 키 남김), `cache(clock)` |
| `FakeJwks.issue_access_token(clock, *, audience, key=None, headers=None, **claims)` | 서명된 액세스 토큰. `claims`는 claim 이름(`sub=`, `scope=`, `acct="member"`, `exp=`, `client_id=`); None은 그 claim을 뺀다. `key`로 공개 안 된 키 서명 |
| `FakeJwks.issue_id_token(clock, *, client_id, nonce, key=None, headers=None, **claims)` | ID 토큰(`aud`=client_id, `auth_time`, `nonce`) |
| `access_token_claims(clock, *, audience, …)`, `id_token_claims(clock, *, client_id, nonce, …)`, `public_jwk(private_key, kid)` | 서명 전 dict·JWK |
| `FakeTokenEndpoint(jwks, clock, *, client_id="test-client", client_secret="test-client-secret", issuer=ISSUER)` | 가짜 sandcorp-auth. `approve(authorize_url, *, sub, acct, scope, access_overrides, id_token_overrides) -> {"code","state"}`(response_type·client_id·S256·필수 파라미터 검사), `approve_member(url)`, `deny(url, error)`. 객체 자체가 `TokenTransport`: Basic 인증(`invalid_client` 401), 일회용 코드·같은 `redirect_uri`·PKCE(`invalid_grant` 400). `requests`에 받은 요청이 쌓이고, `respond(status, body)`·`fail(exc)`로 다음 한 번을 바꾼다(500, 64KB 넘는 본문, `TimeoutError` 등). `scope`에 `openid`가 있으면 ID 토큰도 준다 |
| `bearer_header(token)` | `{"Authorization": "Bearer …"}` — Django test client·RequestFactory·ninja TestClient의 `headers=` |
| 상수 `ISSUER`, `OWNER_SUB`(`farrar142`), `MEMBER_SUB`(형식 맞는 `m_…`), `DEFAULT_START` | |

## 저장소에서 쓰는 법 — 어댑터 한 파일

settings 이름은 저장소마다 다르므로 패키지는 읽지 않는다. 저장소는 `oauth/auth.py`(이름은 자유) 한 파일에서 settings를 함수 인자로 바꾼다.

```python
# oauth/auth.py — 이 저장소에서 인증 설정을 읽는 유일한 곳
from functools import cache

from django.conf import settings

from sandcorp_authkit.django import AuthNotConfigured, BearerAuth, BearerConfig, require_bearer
from sandcorp_authkit.login import LoginConfig
from sandcorp_authkit.resource import metadata_url
from sandcorp_authkit.tokens import JwksCache, SystemClock, http_jwks_fetcher, owner_only

clock = SystemClock()


@cache  # 프로세스마다 캐시 하나(시험은 jwks_cache.cache_clear() 또는 monkeypatch)
def jwks_cache() -> JwksCache:
    return JwksCache(http_jwks_fetcher(f"{settings.AUTH_ISSUER}/.well-known/jwks.json"), clock)


def bearer_config() -> BearerConfig:
    if not settings.AUTH_OWNER_SUB:
        raise AuthNotConfigured("AUTH_OWNER_SUB is empty")  # portfolio·metrics의 503
    return BearerConfig(
        issuer=settings.AUTH_ISSUER,
        audience=settings.AUTH_RESOURCE,
        resource_metadata_url=f"{settings.SITE_URL}/.well-known/oauth-protected-resource",
        jwks=jwks_cache(),
        clock=clock,
        extra_claims_hook=owner_only(settings.AUTH_OWNER_SUB),
    )


def login_config() -> LoginConfig:
    return LoginConfig(
        client_id=settings.AUTH_CLIENT_ID,
        client_secret=settings.AUTH_CLIENT_SECRET,
        redirect_uri=settings.AUTH_REDIRECT_URI,
        authorize_url=f"{settings.AUTH_ISSUER}/authorize",
        token_url=f"{settings.AUTH_ISSUER}/token",
        issuer=settings.AUTH_ISSUER,
        resource=settings.AUTH_RESOURCE,
        scope="login",  # flow: "openid profile email login admin"
    )


admin_auth = BearerAuth("admin", config=bearer_config)  # ninja: @api.get(..., auth=admin_auth)
require_admin = require_bearer("admin", config=bearer_config)  # Django 뷰
```

ninja API를 만드는 곳에서 `install_bearer_errors(api)`를 한 번 부른다. 메타데이터 뷰는 `metadata_response(settings.AUTH_RESOURCE, settings.AUTH_ISSUER, ["admin", "login"])`. RFC 9728 경로가 필요하면 `metadata_url(settings.AUTH_RESOURCE)`.

운영자 로그인 뷰:

```python
from django.contrib.auth import login
from django.shortcuts import redirect, render

from sandcorp_authkit.login import LoginRejected, SessionAttemptStore, complete_login, start_login
from sandcorp_authkit.tokens import owner_only

from . import auth


def start(request):
    try:
        url = start_login(
            auth.login_config(),
            SessionAttemptStore(request.session),
            clock=auth.clock,
            extra={"next": safe_next(request.GET.get("next"))},
        )
    except LoginRejected:
        return render(request, "admin/oauth_failed.html", status=503)
    return redirect(url)


def callback(request):
    try:
        result = complete_login(
            request.GET.dict(),
            auth.login_config(),
            SessionAttemptStore(request.session),
            jwks=auth.jwks_cache(),
            clock=auth.clock,
            extra_claims_hook=owner_only(settings.AUTH_OWNER_SUB),
            transport=auth.token_transport(),  # 시험에서 FakeTokenEndpoint로 바꾸는 자리
        )
    except LoginRejected as exc:
        logger.info("admin login refused: %s", exc.reason)
        return render(request, "admin/oauth_failed.html", status=403)
    user = owner_user(result.access.sub)  # 사이트 몫: 비활성 대표 거절, staff 복구
    login(request, user)  # Django가 세션 키를 바꾼다
    return redirect(safe_next(result.extra.get("next")))  # next는 콜백에서 다시 검사
```

`token_transport()`는 어댑터에서 `None`(= urllib)을 돌려주는 함수로 두고, 시험은 `monkeypatch`로 `FakeTokenEndpoint`를 돌려주게 한다.

시험(conftest):

```python
import pytest

from sandcorp_authkit.testing import FakeJwks, FakeTokenEndpoint, FixedClock, bearer_header

from oauth import auth


@pytest.fixture
def clock(monkeypatch):
    clock = FixedClock()
    monkeypatch.setattr(auth, "clock", clock)
    return clock


@pytest.fixture(autouse=True)
def fake_jwks(monkeypatch, clock, settings):
    settings.AUTH_OWNER_SUB = "owner"
    fake = FakeJwks()
    cache = fake.cache(clock)  # 진짜 JwksCache, 가짜 엔드포인트
    monkeypatch.setattr(auth, "jwks_cache", lambda: cache)
    return fake


@pytest.fixture
def auth_server(monkeypatch, fake_jwks, clock, settings):
    settings.AUTH_CLIENT_ID, settings.AUTH_CLIENT_SECRET = "site-admin", "secret"
    server = FakeTokenEndpoint(fake_jwks, clock, client_id="site-admin", client_secret="secret")
    monkeypatch.setattr(auth, "token_transport", lambda: server)
    return server


def test_admin_api(client, fake_jwks, clock, settings):
    token = fake_jwks.issue_access_token(clock, audience=settings.AUTH_RESOURCE, sub="owner")
    assert client.get("/api/admin/x", headers=bearer_header(token)).status_code == 200


def test_login(client, auth_server):
    start = client.get("/admin/oauth/start/")
    query = auth_server.approve(start["Location"], sub="owner")
    assert client.get("/admin/oauth/callback/", query).status_code == 302
```

### 저장소 fake → 패키지

| 저장소의 것 | 패키지 |
|---|---|
| `FrozenClock(moment)`·`advance` (4곳) | `FixedClock(moment)`·`advance` |
| `public_jwk(private_key, kid)` (4곳) | `public_jwk` |
| `FakeAuthServer.fetch_jwks`·`fetches`·`failing` (portfolio·metrics), `FakeJwksEndpoint.keys`·`fetches` (news·flow) | `FakeJwks()`·`fetches`·`failing`·`serve(*keys)` |
| `rotate(kid)` (portfolio·metrics) | `FakeJwks.rotate(kid)` |
| `issue`/`issue_with(claims, signing_key=, headers=)` (portfolio·metrics), `Signer.token(**overrides)`·`claims()`·`sign(dict)` (news·flow) — None이면 claim 뺌 | `FakeJwks.issue_access_token(clock, audience=, key=, headers=, **claims)`(None이면 뺌), `access_token_claims`, `SigningKey.sign(dict, headers=)` |
| `Signer.member_token` (flow) | `issue_access_token(..., sub=MEMBER_SUB, acct="member", scope="login")` |
| `bearer(token)` (portfolio·metrics) | `bearer_header(token)` |
| `authorize(url)` (portfolio·metrics), `approve(url, sub=, acct=, flow_scope=, id_token_overrides=)`·`approve_member` (flow) | `FakeTokenEndpoint.approve(url, sub=, acct=, scope=, access_overrides=, id_token_overrides=)`·`approve_member` |
| `exchange_code(grant)`·`exchange(config, code=, code_verifier=)` — secret·일회용 코드·redirect_uri·PKCE 검사 (portfolio·metrics·flow) | `FakeTokenEndpoint`를 `transport=`로 |
| `exchanges`/`grants` 기록 (4곳) | `FakeTokenEndpoint.requests` |
| 오류 주입 `TokenExchangeError`/`AuthServerError`/`TokenExchangeFailed` (4곳) | `FakeTokenEndpoint.respond(status, body)`·`fail(exc)` (+ 어디에도 없던 상태 코드·큰 응답·타임아웃) |
| flow ID 토큰(nonce·auth_time·name·email·email_verified) | `issue_id_token`, `approve(id_token_overrides={"name": …})` |
| `make_validator(endpoint, clock, owner_sub=)` (flow) | `BearerConfig(..., jwks=fake.cache(clock), extra_claims_hook=owner_or_member(owner_sub))` |
| 상수 `OWNER`, `MEMBER_SUB`, `ISSUER` | `OWNER_SUB`, `MEMBER_SUB`, `ISSUER` |

저장소마다 남는 것: settings를 채우는 픽스처, 어댑터 seam(monkeypatch 대상)을 바꾸는 픽스처, 기본값(`owner_sub="owner"`, `client_id="portfolio-admin"` 등)을 저장소 시험에 맞추는 한두 줄.

## 정한 것과 근거 (0.2.0: django·login·testing)

네 사이트의 bearer(portfolio·metrics `oauth/bearer.py`, news `core/auth.py`, flow `apps/tenants/auth.py`·`apps/mcp/views.py`)와 운영자 로그인(portfolio·metrics `oauth/login.py`+`adapters/auth_client.py`, news `core/admin_login.py`+`adapters/auth_server.py`, flow `apps/tenants/operator_login.py`)을 비교했다. 다른 곳은 더 엄격한 쪽을 기본으로 삼았다.

**bearer**
- **설정이 비면 503 `auth_not_configured`, 헤더를 보기 전에**(portfolio·metrics). news·flow는 401이었다 — 설정 실수를 「토큰이 틀렸다」로 숨기지 않는다. 대표 sub가 빈 경우는 어댑터의 설정 함수가 `AuthNotConfigured`를 던진다(flow처럼 일반 사용자는 통과시키려면 던지지 않고 `owner_or_member("")`).
- **토큰은 보낸 그대로**(portfolio·metrics·flow 운영자). news·flow MCP는 앞뒤 공백을 지웠다. `Bearer  x`는 토큰 ` x`로 401 `invalid_token`. `Bearer` 대소문자는 네 곳 모두 무시 — 그대로.
- **빈 토큰(`Bearer `)은 「토큰 없음」 401**(portfolio·metrics·news). flow 운영자는 `invalid_token`이었다.
- **본문 `{"error": "unauthorized"|"forbidden"}`**(portfolio·metrics·news·flow MCP). flow 운영자 API의 `{"detail": …}`는 T6이 어댑터에서 `deny()`를 감싸 지킨다.
- **403 헤더에 `resource_metadata` 없음**: 네 곳 다 그렇고 문서 5절도 같다.
- **ninja 거부는 `BearerDenied`가 응답을 싣는다**: 예외 처리기는 요청마다 다른 `resource_metadata_url`(flow는 운영자·MCP가 다르다)을 모르므로, `BearerAuth`가 응답을 만들어 던지고 `install_bearer_errors`는 돌려주기만 한다. 직접 쓰는 `authenticate()`는 원래 예외를 던진다(portfolio의 시험 꼴 그대로).
- **Django 뷰는 토큰을 인자로 + `request.access_token`**: portfolio·metrics는 인자, news는 속성. 둘 다 준다.
- **메타데이터 CORS `*`**: portfolio·metrics가 보냈다 → `metadata_response`.

**login**
| 항목 | portfolio·metrics | news | flow | 패키지 |
|---|---|---|---|---|
| 시도 저장 | 세션 한 칸, pop | 세션 한 칸, pop | 서명 쿠키(읽을 수 있음) | 저장소 인터페이스, 한 칸, `take`가 지움. 문서 7절대로 서버 쪽(`SessionAttemptStore`) |
| 시도 만료 | 세션 수명 | 세션 수명 | 600초 | **600초**(`started_at` + 로그인 시계) |
| nonce | 없음 | 없음 | 32B | **늘 보냄** |
| 콜백 순서 | state → error·code | state → error·code | error → state | **state 먼저**(그다음 만료 → error → code). 남이 꾸민 `error` 콜백도 시도를 소진한다 |
| state 비교 | `compare_digest` | `compare_digest` | `compare_digest` | 같음 |
| Basic 인코딩 | `quote(safe="")` | `quote_plus` | `quote_plus` | **`quote(safe="")`**: 공백을 `%20`으로 — 받는 쪽이 `unquote`든 `unquote_plus`든 같게 풀린다 |
| timeout | 5초 | 5초 | 10초 | **5초** |
| 응답 한도 | 64KB | 없음 | 없음 | **64KB** |
| 리다이렉트 | urllib 기본(따라감) | 따라감 | 따라감 | **따라가지 않음**(3xx는 실패) |
| `token_type` | 안 봄 | 안 봄 | 안 봄 | **`Bearer`(대소문자 무시) 확인** |
| 액세스 토큰 `client_id` | 안 봄 | 안 봄 | 이 클라이언트와 같아야 | **같아야**(flow) |
| ID 토큰 | 안 받음(`scope=login`) | 안 받음 | iss·aud·exp+30·nonce·sub·require iat | flow 전부 + **`iat` 정수, `aud`는 문자열만(배열 거부), `azp` 있으면 client_id, `acct`가 액세스 토큰과 같음, 공개 키 kid만**. `openid`를 요청했으면 필수, 안 했어도 오면 검증 |
| `at_hash` | — | — | 안 봄 | **안 봄**: OIDC에 EdDSA용 정의가 없고 sandcorp-auth도 내지 않는다(`backend/services/oidc.py`) |
| 실패 사유 | 로그만 | 로그만 | URL 쿼리 `login_error=` | `LoginRejected.reason` — 로그·화면 고르기용, URL에 싣지 말 것 |

사이트 몫으로 남긴 것: 대표 계정 찾기·만들기(비활성 대표 거절 — news는 되살렸다, 저장소 티켓에서 고친다), `next` 안전 검사(콜백에서도 다시), `admin` 스코프·진입 종류(flow의 operator/member) 확인, 오류 화면.

**testing**: 네 저장소 fake의 기능을 모두 담았고(위 표), 어디에도 없던 상태 코드·큰 응답·예외 주입을 더했다. 토큰 기본값의 None은 「그 claim을 뺀다」(네 저장소 규칙). T1 시험(`tests/test_tokens.py`)은 conftest가 `testing`의 `FakeJwks`·`SigningKey`·`FixedClock`을 다시 내보내 그대로 돈다.

## 정한 것과 근거 (0.1.0: tokens·resource)

네 사이트의 구현(portfolio `oauth/tokens.py`, metrics `oauth/tokens.py`, news `services/tokens.py`+`adapters/jwks.py`, flow `apps/tenants/resource_token.py`)을 비교해, 다른 곳은 가장 엄격한 쪽을 기본으로 삼았다.

- **검증 규칙은 네 곳이 같다**: `EdDSA`만, `kid` 문자열 필수, 필수 claim `iss sub aud exp iat jti client_id scope`, `exp` 여유 30초(`iat`·`nbf` 시각 비교 없음), `iss`·`aud`는 문자열 완전 일치(배열 `aud` 거부), `scope`는 공백 한 칸으로 나눈 집합의 원소 비교. 그대로 옮겼다.
- **`iat`·`exp`의 `true`/`false` 거부**: news·flow는 거부, portfolio·metrics는 정수로 받았다 → 거부.
- **JWKS 문서가 이상하면 「조회 실패」(J4)**: news·flow는 키 목록을 읽다 난 예외가 검증 밖으로 샜고, portfolio·metrics는 J4로 처리했다 → J4. 문서가 `{"keys": [...]}`가 아니면 실패로 보고 옛 키를 쓴다. 키 하나가 깨졌거나 `kid`가 문자열이 아니면 그 키만 버린다.
- **캐시 잠금**: portfolio·metrics만 잠갔다 → 잠근다(같은 순간 첫 요청이 몰려도 JWKS는 한 번 받는다).
- **`issuer`는 인자**: metrics·flow처럼. 기본값은 두지 않는다(설정은 인자로만).
- **대표 확인(T11)은 훅**: portfolio·metrics·news는 `sub == AUTH_OWNER_SUB`를 본문에서, flow는 `acct` 규칙과 함께 본다. 패키지 본문은 계정 규칙을 모르고 `owner_only`/`owner_or_member` 훅으로 끼운다. 훅은 T10 뒤·S1 앞에 돈다 — 남의 토큰은 스코프와 상관없이 401(기존 순서 그대로).
- **`owner_only`는 `acct`가 있는 토큰도 거부**: 대표 토큰에는 `acct`가 없다(10절 A1). 기존 세 곳은 `sub`만 봤으나, member의 `sub`(`m_…`)가 대표와 같을 수 없어 결과는 같고 규칙은 더 좁다.
- **빈 `owner_sub`는 모든 대표 토큰 거부**: flow와 같다(`TokenRejected`). portfolio·metrics는 설정이 비면 검증 전에 503을 낸다 — 그것은 웹 계층의 `AuthNotConfigured`(0.2.0)가 맡는다.
- **헤더 값 따옴표 깨짐 방지**: `www_authenticate`는 `"`·`\`·제어 문자가 든 값을 이스케이프하지 않고 `ValueError`로 거부한다(값은 설정에서 오므로 이스케이프보다 실수를 드러내는 쪽).
- **메타데이터 경로**: 기존 portfolio·news는 경로 없는 `/.well-known/oauth-protected-resource`와 `/…/mcp` 둘 다에서 같은 본문을 낸다. 패키지는 RFC 9728 경로(`metadata_path`)를 주고, 어디에 붙일지는 사이트가 정한다. `WWW-Authenticate`의 `resource_metadata`도 사이트가 지금 쓰는 URL을 그대로 넘기면 된다(동작 변화 없음).

## 개발

```sh
cd clients/python
uv run pytest            # 시험(외부 네트워크 없음, JWKS·token HTTP는 127.0.0.1 서버, Django는 conftest의 최소 settings)
uv run ruff format --check . && uv run ruff check .
uv run mypy              # strict
```

저장소 루트의 `make check`가 이 셋을 함께 돈다(`make authkit-test|authkit-lint|authkit-typecheck`). 시험 하나의 CPU 한도 1.0초(env `TEST_CPU_LIMIT`)는 backend와 같은 규칙이다(`tests/conftest.py` 끝).

## 버전

`authkit-vX.Y.Z` 태그. 0.1.0: `tokens`·`resource`. 0.2.0: `django`·`login`·`testing`(0.1.0 서명은 그대로, 추가만).
