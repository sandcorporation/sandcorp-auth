# sandcorp-authkit

Sandcorp 자원 서버(portfolio, metrics, news, flow)가 auth.sandcorp.co.kr의 액세스 토큰을 검증하고 RFC 9728 메타데이터·`WWW-Authenticate`를 내는 공용 패키지. 규칙의 원문은 이 저장소 `docs/resource-server-token-validation.md`이고, 스펙은 sandcorp-auth #54.

- Python 3.14 이상, 의존성은 `pyjwt[crypto]`뿐. 웹 프레임워크에 기대지 않는다(Django·ninja 통합은 0.2.0의 extras `[django]`).
- 설정은 함수 인자로만 받는다. 패키지는 settings·환경 변수를 읽지 않는다 — 저장소는 어댑터 한 파일에서 값을 넘긴다.

## 설치

```toml
# pyproject.toml
[project]
dependencies = ["sandcorp-authkit"]

[tool.uv.sources]
sandcorp-authkit = { git = "https://github.com/sandcorporation/sandcorp-auth", subdirectory = "clients/python", tag = "authkit-v0.1.0" }
```

또는 `uv add "sandcorp-authkit @ git+https://github.com/sandcorporation/sandcorp-auth@authkit-v0.1.0#subdirectory=clients/python"`. 태그를 고정하고, 올릴 때는 저장소마다 PR 하나.

## 공개 API (0.1.0)

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

## 정한 것과 근거

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
uv run pytest            # 시험(외부 네트워크 없음, JWKS HTTP는 127.0.0.1 서버)
uv run ruff format --check . && uv run ruff check .
uv run mypy              # strict
```

저장소 루트의 `make check`가 이 셋을 함께 돈다(`make authkit-test|authkit-lint|authkit-typecheck`). 시험 하나의 CPU 한도 1.0초(env `TEST_CPU_LIMIT`)는 backend와 같은 규칙이다(`tests/conftest.py` 끝).

## 버전

`authkit-vX.Y.Z` 태그. 0.1.0: `tokens`·`resource`. 0.2.0(예정): `django`·`login`·`testing`.
