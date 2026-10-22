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

각 사이트의 관리 화면 로그인은 사이트 자신이 **기밀 클라이언트**로서 Authorization Code 플로우를 돈다. 조율자가 이 서비스의 admin에서 사이트마다 기밀 클라이언트를 등록하고 `client_id`·`client_secret`(한 번만 보인다)·리다이렉트 URI를 사이트 설정에 넣는다.

1. 사이트 로그인 버튼 → `https://auth.sandcorp.co.kr/authorize?response_type=code&client_id=…&redirect_uri=…&state=…&code_challenge=…&code_challenge_method=S256&resource=<자기 리소스 URL>&scope=login`. 기밀 클라이언트도 PKCE(S256)는 필수다. `state`와 `code_verifier`는 사이트 세션에 둔다.
2. 대표가 이 서비스에서 로그인(비밀번호 + TOTP)·동의한다.
3. 콜백에서 `state`를 확인하고 `POST https://auth.sandcorp.co.kr/token`(form: `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`; 클라이언트 인증 `client_secret_basic`)으로 교환한다.
4. 받은 `access_token`을 **3절 규칙 그대로**(`aud`=자기 리소스 URL, 요구 스코프 `login`) 검증한다. 통과하면 `sub`는 이미 `AUTH_OWNER_SUB`와 같다(T11).
5. 사이트의 Django 세션을 만든다(사이트 쪽 대표 계정으로 `login()`). 토큰과 리프레시 토큰은 저장하지 않고 버린다. 이후 관리 화면은 Django 세션으로 돈다.

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
