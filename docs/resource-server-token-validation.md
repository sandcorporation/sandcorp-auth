# 리소스 서버 토큰 검증 규칙

portfolio(`https://sandcorp.co.kr`)와 뉴스(`https://news.sandcorp.co.kr`)가 이 서비스(auth.sandcorp.co.kr)가 발급한 **액세스 토큰**을 검증하는 규칙. 두 사이트는 이 문서만 보고 PyJWT로 각자 구현한다(공용 패키지 없음). 규칙은 「권장」이 아니라 전부 **필수**다. 값은 아래 표 그대로 쓴다.

용어는 [GLOSSARY.md](../GLOSSARY.md)를 따른다: 대표(Owner), 클라이언트(Client), 리소스(Resource), 스코프(Scope), 동의(Consent).

## 1. 고정 값

| 이름 | 값 |
|---|---|
| 발급자 `iss` | `https://auth.sandcorp.co.kr` |
| JWKS | `https://auth.sandcorp.co.kr/.well-known/jwks.json` |
| 인가 서버 메타데이터(RFC 8414) | `https://auth.sandcorp.co.kr/.well-known/oauth-authorization-server` |
| 서명 알고리즘 | `EdDSA`(Ed25519)만. JWK는 `kty=OKP`, `crv=Ed25519` |
| 액세스 토큰 수명 | 10분(`exp - iat = 600`) |
| 키 회전 유예 | 10분. 회전 후 이전 키는 10분 동안 JWKS에 남는다 |
| JWKS 캐시 TTL | 600초 |
| 모르는 `kid` 재조회 간격 | 최소 60초(60초 안에 두 번 재조회하지 않는다) |
| JWKS 조회 실패 후 재시도 간격 | 60초 |
| JWKS 조회 타임아웃 | 5초 |
| `exp` 허용 오차 | 30초(`now > exp + 30`이면 만료) |
| portfolio 리소스(`aud`) | `https://sandcorp.co.kr/mcp` |
| 뉴스 리소스(`aud`) | `https://news.sandcorp.co.kr/mcp` |
| `sub` | 대표 계정의 username(예: `farrar142`). 사이트 설정값 `AUTH_OWNER_SUB`와 비교 |

### 스코프

스코프는 리소스에 속한다. 같은 이름이라도 `aud`가 다르면 다른 권한이다.

| 리소스 | 스코프 | 뜻 |
|---|---|---|
| `https://sandcorp.co.kr/mcp` | `admin` | portfolio 관리(MCP·관리 API) |
| `https://sandcorp.co.kr/mcp` | `login` | portfolio 관리 화면 로그인 |
| `https://news.sandcorp.co.kr/mcp` | `admin` | 뉴스 관리(MCP·관리 API) |
| `https://news.sandcorp.co.kr/mcp` | `editor` | 뉴스 편집자 권한(기사 작성·수정) |
| `https://news.sandcorp.co.kr/mcp` | `login` | 뉴스 관리 화면 로그인 |

OIDC 로그인 정보 스코프(`openid`·`profile`·`email`)는 리소스 스코프가 아니다. 사이트 토큰의 `aud`·`scope`에는 나타나지 않으므로(그 스코프만 요청한 토큰의 `aud`는 내부 리소스 `https://auth.sandcorp.co.kr/userinfo`) 이 규칙은 그대로다.

엔드포인트마다 필요한 스코프 **하나**를 정한다. 관리 화면 로그인 콜백은 `login`을 요구한다.

## 2. 토큰 모양

헤더:

```json
{"alg": "EdDSA", "typ": "JWT", "kid": "<키 식별자>"}
```

클레임(모두 필수):

| 클레임 | 타입 | 예 |
|---|---|---|
| `iss` | 문자열 | `"https://auth.sandcorp.co.kr"` |
| `sub` | 문자열 | `"<대표 username>"` |
| `aud` | 문자열(배열 아님) | `"https://news.sandcorp.co.kr/mcp"` |
| `client_id` | 문자열 | `"Zf3k..."` |
| `scope` | 문자열, 공백 구분 | `"admin editor"` |
| `iat` | 정수(유닉스 초) | `1767225600` |
| `exp` | 정수(유닉스 초) | `1767226200` |
| `jti` | 문자열 | `"9b1d..."` |

이 서비스는 id_token과 userinfo를 주지 않는다. 사이트가 받는 신원 정보는 액세스 토큰의 `sub` 하나다.

일반 사용자(ADR 0003)의 토큰에는 위 클레임에 더해 `"acct": "member"`가 있고 `sub`는 `m_` + ULID다. **대표 토큰에는 `acct`가 없다.** 이 절의 규칙(T11)은 그대로이고, 일반 사용자를 받는 사이트만 10절을 따른다.

## 3. 검증 규칙

순서대로 적용한다. 하나라도 어기면 거부한다. T1~T11 위반은 **401 `invalid_token`**, S1 위반만 **403 `insufficient_scope`** 이다.

### 토큰 받기

- **B1.** 토큰은 `Authorization: Bearer <토큰>` 헤더로만 받는다. 쿼리 문자열·폼 본문·쿠키의 토큰은 보지 않는다. 스킴 `Bearer`는 대소문자를 가리지 않는다.
- **B2.** `Authorization` 헤더가 없거나 스킴이 `Bearer`가 아니면 「토큰 없음」 401(아래 5절, `error` 없음).

### 헤더와 키

- **T1.** 헤더를 서명 검증 없이 읽을 수 없으면(JWS 세 부분이 아니면, base64·JSON이 깨졌으면) 거부.
- **T2.** 헤더 `alg`가 정확히 `EdDSA`가 아니면 거부(`none`, `HS256`, `RS256`, `ES256` 등 모두). PyJWT에는 `algorithms=["EdDSA"]`만 넘긴다.
- **T3.** 헤더 `kid`가 문자열로 없으면 거부.
- **T4.** `kid`로 JWKS 캐시에서 공개 키를 고른다(4절 규칙). 그래도 없으면 거부.
- **T5.** 그 키로 서명이 맞지 않으면 거부.

### 클레임

- **T6.** `iss`·`sub`·`aud`·`client_id`·`scope`·`iat`·`exp`·`jti` 중 하나라도 없으면 거부.
- **T7.** 타입이 2절 표와 다르면 거부(`iat`·`exp`가 정수가 아니거나, `aud`가 배열이거나, 나머지가 문자열이 아니면).
- **T8.** `iss`가 `https://auth.sandcorp.co.kr`와 정확히 같지 않으면 거부(끝 `/` 붙은 것도 거부).
- **T9.** `aud`가 자기 리소스 URL과 정확히 같지 않으면 거부. 문자열 완전 일치만 인정한다: 배열, 끝 `/`, 대소문자 차이, 다른 사이트의 URL 모두 거부. portfolio는 `https://sandcorp.co.kr/mcp`, 뉴스는 `https://news.sandcorp.co.kr/mcp`.
- **T10.** 현재 시각(유닉스 초)이 `exp + 30`보다 크면 거부. `iat`·`nbf`는 시각 비교를 하지 않는다(존재·타입만 T6·T7).
- **T11.** `sub`가 설정값 `AUTH_OWNER_SUB`와 정확히 같지 않으면(대소문자 구분, 앞뒤 공백 없이) 거부.

### 스코프

- **S1.** `scope`를 공백 한 칸(`" "`)으로 나눠 빈 조각을 버린 집합에 엔드포인트가 요구하는 스코프가 **원소로** 들어 있지 않으면 403. 부분 문자열 비교 금지(`administrator`는 `admin`이 아니다).

`jti`는 거부 목록과 대조하지 않는다. 토큰을 즉시 끊는 수단은 리프레시 토큰 폐기이고, 이미 나간 액세스 토큰은 최대 10분 뒤 만료된다.

## 4. JWKS 캐시

- **J1.** 프로세스마다 `kid → 공개 키` 캐시 하나를 둔다. 비어 있거나 마지막 성공 조회에서 600초가 지났으면 다음 검증 때 `GET https://auth.sandcorp.co.kr/.well-known/jwks.json`(타임아웃 5초)으로 다시 받는다.
- **J2.** 캐시가 신선한데 토큰의 `kid`가 캐시에 없으면 **그 자리에서 1회** 다시 받는다. 단 직전의 「모르는 `kid` 재조회」에서 60초가 지나지 않았으면 다시 받지 않고 그대로 거부한다(모르는 `kid`를 뿌리는 요청이 JWKS를 두드리지 못하게).
- **J3.** 받은 JWKS에서 `kty=OKP`, `crv=Ed25519`이고 `alg`가 있으면 `EdDSA`, `use`가 있으면 `sig`인 키만 쓴다. 나머지는 버린다. 성공한 조회는 캐시를 통째로 바꾼다(JWKS에서 빠진 키는 캐시에서도 빠진다).
- **J4.** 조회가 실패하면(네트워크 오류, 타임아웃, 2xx 아님, JSON 깨짐) 기존 캐시를 그대로 쓰고, 60초 동안 다시 시도하지 않는다. 키를 찾지 못하면 T4로 401이다.
- **J5.** 키 회전: 인가 서버는 새 키로 서명을 시작하고 이전 키를 10분 동안 JWKS에 남긴다. 새 `kid`는 J2로 즉시 따라가고, 이전 키로 서명된 토큰은 그 10분 안에 스스로 만료된다. 사이트는 따로 할 일이 없다.

## 5. 실패 응답

`<site>`는 사이트 원점이다: `https://sandcorp.co.kr` 또는 `https://news.sandcorp.co.kr`. 헤더 값은 아래 문자열 그대로(따옴표·쉼표·공백 포함) 쓴다.

| 경우 | 상태 | `WWW-Authenticate` |
|---|---|---|
| 토큰 없음(B2) | 401 | `Bearer resource_metadata="https://<site>/.well-known/oauth-protected-resource"` |
| 토큰이 틀림(T1~T11) | 401 | `Bearer resource_metadata="https://<site>/.well-known/oauth-protected-resource", error="invalid_token"` |
| 스코프 부족(S1) | 403 | `Bearer error="insufficient_scope", scope="<요구 스코프>"` |

예(뉴스, 토큰 만료):

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://news.sandcorp.co.kr/.well-known/oauth-protected-resource", error="invalid_token"
```

본문은 사이트 관례대로 두되 거부 이유(어느 규칙인지)를 응답에 싣지 않는다. 이유는 서버 로그에만 남긴다.

## 6. 보호 리소스 메타데이터(RFC 9728)

각 사이트는 `GET /.well-known/oauth-protected-resource`에 인증 없이 다음 JSON을 `Content-Type: application/json`으로 돌려준다.

portfolio(`https://sandcorp.co.kr/.well-known/oauth-protected-resource`):

```json
{
  "resource": "https://sandcorp.co.kr/mcp",
  "authorization_servers": ["https://auth.sandcorp.co.kr"],
  "scopes_supported": ["admin", "login"],
  "bearer_methods_supported": ["header"]
}
```

뉴스(`https://news.sandcorp.co.kr/.well-known/oauth-protected-resource`):

```json
{
  "resource": "https://news.sandcorp.co.kr/mcp",
  "authorization_servers": ["https://auth.sandcorp.co.kr"],
  "scopes_supported": ["admin", "editor", "login"],
  "bearer_methods_supported": ["header"]
}
```

클라이언트(claude.ai 커넥터, Claude Code)는 401의 `resource_metadata`로 이 문서를 찾고, `authorization_servers`로 이 서비스를 찾아 인가를 시작한다. 인가 요청의 `resource` 파라미터는 위 `resource` 값이다.

## 7. 관리 화면 로그인(기밀 클라이언트)

각 사이트의 관리 화면 로그인은 사이트 자신이 **기밀 클라이언트**로서 Authorization Code 플로우를 돈다. 조율자가 사이트마다 기밀 클라이언트를 등록하고 `client_id`·`client_secret`·리다이렉트 URI를 사이트 설정에 넣는다. 시크릿은 발급할 때 **한 번만** 보이고 이 서비스에는 해시만 남는다 — 잃어버리면 다시 발급한다(옛 시크릿은 즉시 무효).

```sh
cd backend && uv run python manage.py clients create-confidential --name "뉴스 관리" --redirect-uri https://news.sandcorp.co.kr/auth/callback
# 재발급: clients rotate-secret --client-id <id>   목록: clients list
```

admin(클라이언트 → 추가)에서도 만들 수 있다. 추가 폼은 기밀 클라이언트 전용(이름·리다이렉트 URI)이고, 저장 뒤 메시지로 시크릿을 한 번 보여 준다. 변경 화면의 「시크릿 재발급」 버튼도 같다.

### 두 사이트의 값

| 사이트 | 리다이렉트 URI | 토큰 인증 | resource | scope |
| --- | --- | --- | --- | --- |
| portfolio | `https://sandcorp.co.kr/<admin 경로>/oauth/callback/` (**끝 슬래시 포함**, 정확한 값은 배포 때 조율자가 등록) | `client_secret_basic` | `https://sandcorp.co.kr/mcp` | `login` |
| 뉴스 | `https://news.sandcorp.co.kr/auth/callback` (끝 슬래시 없음) | `client_secret_basic` | `https://news.sandcorp.co.kr/mcp` | `login` |

`redirect_uri`는 등록값과 **문자 하나까지 같아야** 한다(인가 요청과 토큰 교환 둘 다). `.../callback/`와 `.../callback`은 다른 값이다. 기밀 클라이언트의 리다이렉트 URI는 https만 등록된다.

### 흐름

1. 사이트 로그인 버튼 → `https://auth.sandcorp.co.kr/authorize?response_type=code&client_id=…&redirect_uri=…&state=…&code_challenge=…&code_challenge_method=S256&resource=<자기 리소스 URL>&scope=login`. 기밀 클라이언트도 PKCE(S256)는 필수다(없으면 `error=invalid_request`로 돌아온다). `state`(무작위)와 `code_verifier`(43~128자)는 **사이트의 서버 쪽 세션**에 두고, 콜백에서 한 번 쓰고 지운다. 쿠키나 URL에 `code_verifier`를 싣지 않는다.
2. 대표가 이 서비스에서 로그인(비밀번호 + TOTP)·동의한다.
3. 콜백에서 `error` 파라미터가 있으면 로그인 실패로 끝낸다. 없으면 `state`가 세션의 값과 같은지 확인하고(다르면 거부) `code`를 토큰으로 교환한다(아래 요청 예).
4. 받은 `access_token`을 **3절 규칙 그대로**(`aud`=자기 리소스 URL, 요구 스코프 `login`) 검증한다. 통과하면 `sub`는 이미 `AUTH_OWNER_SUB`와 같다(T11).
5. 사이트의 Django 세션을 만든다(사이트 쪽 대표 계정으로 `login()`). 액세스 토큰은 검증에만 쓰고 저장하지 않는다. 응답의 `refresh_token`은 **버려도 된다**(관리 화면은 이후 Django 세션으로 돈다).

### 토큰 요청

```http
POST /token HTTP/1.1
Host: auth.sandcorp.co.kr
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<코드>&redirect_uri=https%3A%2F%2Fnews.sandcorp.co.kr%2Fauth%2Fcallback&code_verifier=<verifier>
```

`client_secret_basic`이면 폼에 `client_id`를 넣지 않아도 된다. 대안 `client_secret_post`는 Basic 헤더 대신 폼에 `client_id`와 `client_secret`을 넣는다. 둘 중 하나만 쓴다.

성공(200):

```json
{"access_token": "eyJ…", "token_type": "Bearer", "expires_in": 600, "refresh_token": "…", "scope": "login"}
```

필드는 RFC 6749 표준 다섯 개뿐이다. 응답에는 `Cache-Control: no-store`가 붙는다.

실패 본문은 RFC 6749 5.2 형식 `{"error": "…", "error_description": "…"}`이다.

| 경우 | 상태 | `error` |
| --- | --- | --- |
| 시크릿이 틀림·없음, 공개 클라이언트가 시크릿을 보냄 | 401 + `WWW-Authenticate: Basic realm="auth.sandcorp.co.kr", error="invalid_client", …` | `invalid_client` |
| 코드가 틀림·만료·이미 씀, `redirect_uri`가 인가 요청 때와 다름, `code_verifier`가 맞지 않음 | 400 | `invalid_grant` |

### 로그아웃과 세션 만료

- 이 서비스에는 **end-session(로그아웃) 엔드포인트가 없다.** 사이트의 로그아웃은 사이트 자기 Django 세션만 끊는다. 받은 리프레시 토큰을 보관했다면 RFC 7009 `POST /revoke`(같은 클라이언트 인증)로 폐기할 수 있다. 이 서비스의 대표 세션(`/logout`)은 사이트와 따로 산다.
- 사이트의 관리 화면 세션은 **12시간 이하**로 둔다(`SESSION_COOKIE_AGE`, 브라우저를 닫으면 끝나도록 `SESSION_EXPIRE_AT_BROWSER_CLOSE`도 권한다). 만료되면 위 흐름을 다시 돈다 — 이 서비스의 대표 세션과 동의가 살아 있으면 비밀번호·동의 없이 바로 돌아온다.

이 서비스는 OIDC를 하지 않는다: id_token, userinfo 엔드포인트, `openid` 스코프가 없다. 신원은 4단계의 액세스 토큰 `sub`로만 확인한다.

## 8. PyJWT 예시

의존성: `pyjwt[crypto]`(PyJWT 2.10 이상, `cryptography` 포함). 아래는 참조 구현을 줄인 것이다. 시험된 원본은 9절의 파일이다.

```python
from collections.abc import Callable
from datetime import datetime
import json
import urllib.request

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ISSUER = "https://auth.sandcorp.co.kr"
JWKS_URL = "https://auth.sandcorp.co.kr/.well-known/jwks.json"
ALGORITHM = "EdDSA"
REQUIRED_CLAIMS = ["iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope"]


def fetch_jwks() -> dict:
    with urllib.request.urlopen(JWKS_URL, timeout=5) as response:  # 2xx 아니면 예외
        return json.load(response)


class JwksCache:  # J1~J4: 참조 구현의 JwksCache를 그대로 옮긴다
    def __init__(self, fetch_jwks: Callable[[], dict], clock) -> None: ...
    def key_for(self, kid: str) -> Ed25519PublicKey | None: ...


class TokenRejected(Exception): ...          # → 401 invalid_token


class InsufficientScope(Exception):         # → 403 insufficient_scope
    def __init__(self, required_scope: str) -> None:
        super().__init__(required_scope)
        self.required_scope = required_scope


def validate_access_token(token, *, jwks, audience, owner_sub, required_scope, clock) -> dict:
    try:
        header = jwt.get_unverified_header(token)                       # T1
    except jwt.InvalidTokenError as exc:
        raise TokenRejected from exc
    kid = header.get("kid")
    if header.get("alg") != ALGORITHM or not isinstance(kid, str):     # T2, T3
        raise TokenRejected
    key = jwks.key_for(kid)                                             # T4
    if key is None:
        raise TokenRejected
    try:
        claims = jwt.decode(                                            # T5, T6
            token, key, algorithms=[ALGORITHM],
            options={"require": REQUIRED_CLAIMS, "verify_aud": False, "verify_iss": False,
                     "verify_exp": False, "verify_iat": False, "verify_nbf": False},
        )
    except jwt.InvalidTokenError as exc:
        raise TokenRejected from exc
    if not (all(isinstance(claims[n], str) for n in ("sub", "client_id", "jti", "scope"))
            and isinstance(claims["iat"], int) and isinstance(claims["exp"], int)):
        raise TokenRejected                                             # T7
    if claims["iss"] != ISSUER:                                         # T8
        raise TokenRejected
    if claims["aud"] != audience:                                       # T9 (배열이면 여기서 다르다)
        raise TokenRejected
    if clock.now().timestamp() > claims["exp"] + 30:                    # T10
        raise TokenRejected
    if claims["sub"] != owner_sub:                                      # T11
        raise TokenRejected
    scopes = set(claims["scope"].split(" ")) - {""}
    if required_scope not in scopes:                                    # S1
        raise InsufficientScope(required_scope)
    return claims
```

`aud`·`iss`·`exp`를 PyJWT 내장 검사에 맡기지 않는 까닭: PyJWT의 `audience` 검사는 배열 `aud`도 통과시키고(T9 위반), `exp` 검사는 시계를 주입할 수 없다. 운영에서는 `clock`에 `datetime.now(UTC)`를 돌려주는 객체를 넘긴다.

Django 뷰에서 쓰는 모양(뉴스 예):

```python
from datetime import UTC, datetime

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


SITE = "https://news.sandcorp.co.kr"
RESOURCE = "https://news.sandcorp.co.kr/mcp"
META = f'resource_metadata="{SITE}/.well-known/oauth-protected-resource"'
jwks = JwksCache(fetch_jwks, SystemClock())  # 프로세스당 하나


def require_scope(request: HttpRequest, scope: str) -> HttpResponse | None:
    auth = request.headers.get("Authorization", "")
    kind, _, token = auth.partition(" ")
    if kind.lower() != "bearer" or not token:                           # B1, B2
        return _deny(401, f"Bearer {META}")
    try:
        validate_access_token(token, jwks=jwks, audience=RESOURCE,
                              owner_sub=settings.AUTH_OWNER_SUB, required_scope=scope,
                              clock=SystemClock())
    except TokenRejected:
        return _deny(401, f'Bearer {META}, error="invalid_token"')
    except InsufficientScope as exc:
        return _deny(403, f'Bearer error="insufficient_scope", scope="{exc.required_scope}"')
    return None


def _deny(status: int, challenge: str) -> HttpResponse:
    response = JsonResponse({"error": "unauthorized" if status == 401 else "forbidden"},
                            status=status)
    response["WWW-Authenticate"] = challenge
    return response
```

## 9. 참조 구현

참조 구현: `backend/tests/reference_validator.py`

규칙과 값의 원본은 이 문서이고, 그 파일은 이 문서를 그대로 옮긴 것이다. 시험(`backend/tests/test_reference_validator.py`)이 통과·거부 사례(다른 `aud`, 만료, 다른 키 서명, `alg` 변조 `HS256`·`none`, 스코프 부족, 모르는 `kid` 재조회, `iss` 불일치, JWKS TTL·재조회 제한·조회 실패)를 고정 시계로 확인한다. 이 서비스의 발급 시험도 실제 발급 토큰을 이 검증기에 통과시킨다. 규칙을 바꾸면 문서·참조 구현·시험을 같은 커밋에서 고친다.

## 10. 일반 사용자를 받는 사이트

대표만 받는 사이트(portfolio, 뉴스, metrics, MCP)는 이 절을 보지 않는다 — T11이 일반 사용자 토큰을 거른다. 일반 사용자(Sandcorp 계정, ADR 0003)도 받는 사이트(Sandcorp Flow 등)만 이 규칙을 쓴다. 그 사이트의 클라이언트는 auth 쪽에서 「일반 사용자 허용」이 켜져 있어야 한다(`manage.py clients members --client-id <id> --allow`, 조율자).

### 클레임

| 클레임 | 대표 토큰 | 일반 사용자 토큰 |
|---|---|---|
| `acct` | **없음** | `"member"` (문자열) |
| `sub` | `"farrar142"` (`AUTH_OWNER_SUB`) | `"m_"` + ULID 26자, 예 `"m_01JB2Z3Y4X5W6V7T8S9R0Q1P2N"` (정규식 `^m_[0-7][0-9A-HJKMNP-TV-Z]{25}$`, 대소문자 구분) |
| `scope` | 동의한 스코프 | `login`, 그리고 그 리소스가 「일반 사용자 허용」으로 표시한 스코프(아래 「받을 수 있는 스코프」). `admin`·`editor`는 절대 없다 |

나머지 클레임(2절 표)은 같다. `sub`는 바뀌지 않는 키다 — 앱의 사용자·테넌트·역할은 `sub`로 묶고 이메일로 묶지 않는다.

### 받을 수 있는 스코프(#47)

일반 사용자가 받을 수 있는 스코프 = `login` ∪ 로그인 정보 스코프(`openid`·`profile`·`email`) ∪ **요청한 `resource`에 속하면서 auth 쪽에서 「일반 사용자 허용」(`Scope.members_allowed`)이 켜진 스코프**. 판정은 리소스 기준이다 — 다른 리소스에 같은 이름의 허용 스코프가 있어도 이 리소스에서 꺼져 있으면 거부한다. `admin`·`editor`는 어느 리소스에서도 켤 수 없다. 켜고 끄는 것은 조율자(`manage.py scopes members --resource <url> --name <scope> --allow|--deny`, `docs/operations.md`). 예: Flow MCP(`https://flow.sandcorp.co.kr/mcp`)의 `flow.read`·`flow.write`.

사이트 쪽 함의: S1(필요한 스코프가 `scope`에 있는가)은 그대로다. 스코프는 「auth가 이 사용자에게 이 토큰을 서명해 줄 수 있다」일 뿐이고, **그 사용자가 실제로 무엇을 할 수 있는지(테넌트 멤버십·역할)는 사이트가 `sub`로 판정한다** — 예를 들어 `flow.write`가 실렸어도 쓰기는 그 테넌트의 Admin에게만 연다.

### 검증 규칙

T1~T10은 3절 그대로, **T11 대신 A1~A3**, 그다음 S1.

- **A1.** `acct` 클레임이 **없으면** 대표 토큰이다. `sub`가 `AUTH_OWNER_SUB`와 정확히 같지 않으면 거부(T11과 같다).
- **A2.** `acct`가 있는데 값이 문자열 `"member"`와 정확히 같지 않으면 거부(`"owner"`, 대소문자 차이, 빈 문자열, 배열, `null` 모두 거부).
- **A3.** `acct`가 `"member"`인데 `sub`가 위 정규식에 맞지 않으면 거부.

A1~A3 위반은 401 `invalid_token`. 대표 전용 기능(그 사이트의 관리 화면 등)은 A1을 통과한 토큰(`acct` 없음)에만 연다 — 일반 사용자 토큰의 스코프로 판단하지 않는다.

### ID 토큰과 userinfo(로그인 정보 스코프)

일반 사용자를 받는 앱은 보통 기밀 클라이언트로 `openid`(필요하면 `profile`·`email`)를 요청해 신원을 받는다(ADR 0001). 일반 사용자의 ID 토큰과 `/userinfo` 응답:

| 클레임 | 언제 | 값 |
|---|---|---|
| `sub` | 언제나 | 위 `m_` ULID |
| `acct` | 언제나 | `"member"` (대표는 없음) |
| `name` | `profile`이고 표시 이름이 있을 때 | 표시 이름 |
| `email`, `email_verified` | `email`이고 이메일이 있을 때만 | 이메일, 그리고 제공자가 검증했는지(불리언). **이메일이 없으면 두 클레임 모두 없다**(Kakao는 이메일이 선택 동의다). 이메일이 필요한 앱은 없을 때 사용자에게 입력받는다 |

일반 사용자에게는 `preferred_username`이 없다(username이 곧 `sub`). ID 토큰의 나머지(`iss`·`aud`=`client_id`·`iat`·`exp`·`auth_time`·`nonce`)는 대표와 같다.

### auth가 거절하는 경우

- 「일반 사용자 허용」이 꺼진 클라이언트로 일반 사용자가 `/authorize`에 오면 동의 화면 없이 `redirect_uri?error=access_denied&state=…`로 돌아간다. 코드 교환·리프레시 사이에 표시가 꺼지면 `/token`이 400 `invalid_grant`.
- 일반 사용자가 위 「받을 수 있는 스코프」 밖의 스코프(`admin`, `editor`, 그 리소스에서 허용되지 않은 스코프)를 요청하면 `error=invalid_scope`로 돌아간다(빼고 발급하지 않는다). 코드 교환·리프레시 사이에 스코프의 허용이 꺼지면 `/token`이 400 `invalid_grant`.
- 탈퇴(#39): 탈퇴한 일반 사용자는 그 즉시 `/authorize`·`/token`(코드·리프레시 400 `invalid_grant`)·`/userinfo`(401)가 모두 거절된다. 이미 받은 액세스 토큰은 만료(최대 10분)까지 서명상 유효하므로, 사이트는 아래 11절의 `user.deleted` 웹훅을 받아 그 `sub`의 세션·데이터를 정리한다.
- 약관(#37): 현재 약관 버전에 동의하지 않은 일반 사용자(첫 가입, 또는 새 버전 시행 뒤)는 `/authorize`에서 auth의 동의 화면을 먼저 보고, 동의하면 같은 인가 요청으로 돌아온다 — 사이트는 할 일이 없다. 다만 새 버전이 시행되면 그 사용자의 코드 교환·리프레시가 400 `invalid_grant`가 되므로, 리프레시 실패 때 사이트는 로그인(`/authorize`)부터 다시 시작한다.

참조 구현은 `backend/tests/reference_validator.py`의 `validate_account_access_token`(반환값 `acct`가 `"owner"` 또는 `"member"`), 시험은 `backend/tests/test_reference_validator.py`, `backend/tests/test_members.py`, `backend/tests/test_member_scopes.py`.

## 11. 탈퇴 웹훅(`user.deleted`)

일반 사용자가 탈퇴하면(ADR 0004) auth는 그 사용자가 **한 번이라도 동의한 클라이언트** 중 웹훅 URL이 있는 곳에 `user.deleted`를 보낸다. 받는 사이트는 그 `sub`의 로그인 세션을 끝내고, 그 사용자에게 딸린 개인정보를 사이트의 보유 규칙대로 지운다. 같은 사람이 같은 소셜 계정으로 다시 가입해도 **새 `sub`**가 되므로 옛 `sub`의 데이터를 새 계정에 이어 붙이지 않는다.

### 등록

auth 운영자가 클라이언트마다 웹훅 URL(https만)을 정하면 서명 비밀이 **한 번만** 출력된다(`docs/operations.md` 11절). 사이트는 그 비밀을 env 등에 넣는다.

```bash
python manage.py clients webhook --client-id <id> --url https://news.sandcorp.co.kr/auth/webhook
# 비밀 재발급(옛 것은 즉시 무효): clients webhook --client-id <id> --rotate-secret
```

### 요청 모양

`POST <웹훅 URL>`, `Content-Type: application/json`. 본문(바이트 그대로 서명된다 — 다시 직렬화하지 말고 받은 바이트로 검증한다):

```json
{"id":"01JB0Z8F3W4Q2Y6K7M9N0P1R2S","type":"user.deleted","sub":"m_01J9…","occurred_at":"2026-10-24T03:15:00Z"}
```

| 헤더 | 값 |
|---|---|
| `X-Sandcorp-Signature` | `t=<보낸 시각, 유닉스 초>,v1=<hex HMAC-SHA256(비밀, "<t>.<본문>")>` |
| `X-Sandcorp-Event` | `user.deleted` |
| `X-Sandcorp-Delivery` | 본문의 `id`와 같다(이벤트 ULID) |

- `occurred_at`은 탈퇴 시각(UTC), `t`는 이번 시도를 보낸 시각이다. 재시도마다 `t`와 서명은 새로 계산되지만 본문과 `id`는 같다.
- 2xx로 답하면 끝이다. 그 밖(3xx 포함 — 리다이렉트를 따라가지 않는다)이나 연결 실패면 5분·15분·1시간·3시간·6시간·12시간·24시간 뒤 다시 보내고, 8번째 시도도 실패하면 포기한다(전송기는 5분마다 돌므로 실제 간격은 최대 5분 늦다).

### 받는 쪽 검증 규칙

- **W1.** `X-Sandcorp-Signature`에서 `t`와 `v1`을 꺼낸다. 형식이 틀리면 거부(400).
- **W2.** `|지금 − t| ≤ 300초`가 아니면 거부(400). 시계가 맞아야 한다(NTP).
- **W3.** `HMAC-SHA256(비밀, "<t>." + 받은 본문 바이트)`의 hex가 `v1`과 같아야 한다. 비교는 상수 시간(`hmac.compare_digest`). 다르면 거부(401).
- **W4.** 본문의 `id`를 이미 처리했으면 아무것도 하지 않고 2xx(재시도·중복 전송). 처리한 `id`는 적어도 3일(재시도 기간보다 길게) 기억한다.
- **W5.** `type`이 `user.deleted`면 `sub`의 세션·데이터를 정리하고 2xx. 모르는 `type`은 무시하고 2xx(나중에 종류가 늘 수 있다).
- 처리는 짧게 끝낸다(10초 안에 답하지 않으면 실패로 보고 다시 보낸다). 무거운 정리는 큐에 넣고 먼저 2xx로 답한다.

### Python 예시

```python
import hashlib
import hmac
import json
import time

TOLERANCE_SECONDS = 300


class WebhookRejected(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status


def verify_sandcorp_webhook(
    secret: str, body: bytes, signature_header: str, *, now: float | None = None
) -> dict:
    """W1~W3. 받은 본문 바이트와 X-Sandcorp-Signature 헤더로 검증하고 이벤트를 돌려준다."""
    parts = dict(item.split("=", 1) for item in signature_header.split(",") if "=" in item)
    try:
        timestamp = int(parts["t"])
        given = parts["v1"]
    except (KeyError, ValueError):
        raise WebhookRejected(400, "bad signature header") from None
    current = time.time() if now is None else now
    if abs(current - timestamp) > TOLERANCE_SECONDS:
        raise WebhookRejected(400, "stale timestamp")
    expected = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, given):
        raise WebhookRejected(401, "bad signature")
    return json.loads(body)


# 사용(Django 예):
# event = verify_sandcorp_webhook(SECRET, request.body, request.headers["X-Sandcorp-Signature"])
# if seen(event["id"]): return 200                       # W4
# if event["type"] == "user.deleted": forget_user(event["sub"])   # W5
# remember(event["id"]); return 200
```

이 예시는 `backend/tests/test_withdrawal.py`가 이 문서에서 그대로 꺼내 auth가 보낸 실제 요청으로 시험한다(문서와 구현이 어긋나면 시험이 깨진다).

