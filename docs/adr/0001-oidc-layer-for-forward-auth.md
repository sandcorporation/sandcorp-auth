# 0001. forward auth를 위해 OAuth 위에 OIDC 층을 얹는다

- 상태: 채택 (2026-10-23, #28)

## 배경

oracle의 Authelia를 sandcorp-auth로 바꾸기로 했다. NPMplus는 oauth2-proxy를 forward auth 업스트림으로 쓸 수 있고, oauth2-proxy는 OpenID Connect 제공자만 있으면 어느 도메인의 호스트든 지킨다. sandcorp-auth는 지금까지 RFC 8707 `resource`가 필수인 OAuth 인가 서버였고, 액세스 토큰의 `aud`는 언제나 리소스 URL 문자열 하나다. 두 사이트(portfolio, 뉴스)가 이 규칙(`docs/resource-server-token-validation.md`)으로 토큰을 검증한다.

## 결정

1. **로그인 정보 스코프(`openid`·`profile`·`email`)는 리소스 스코프가 아니다.** `resource` 없이 `openid`가 오면 그랜트를 내부 리소스 `https://auth.sandcorp.co.kr/userinfo`(마이그레이션 0007)에 묶는다. 이 리소스가 액세스 토큰의 `aud`가 되고, 그 토큰은 `/userinfo`에서만 받는다. 그래서 「그랜트마다 리소스 하나, `aud`는 문자열 하나」라는 기존 불변식이 그대로 선다.
2. `resource`와 `openid`가 함께 오면 액세스 토큰은 그 리소스의 것(그 리소스의 스코프만 `scope` 클레임에)이고, ID 토큰이 따로 붙는다. 리소스 서버가 보는 토큰 모양은 바뀌지 않는다.
3. **ID 토큰의 `aud`는 `client_id`**, 서명은 액세스 토큰과 같은 활성 Ed25519 키(`EdDSA`, 헤더 `kid`). discovery의 `id_token_signing_alg_values_supported`는 `["EdDSA"]`뿐이다. OIDC Discovery는 RS256을 MUST로 적지만, 키 종류를 둘로 늘리면 회전·JWKS·검증 규칙이 모두 두 갈래가 된다. 실제 oauth2-proxy v7.12.0(go-oidc)이 EdDSA ID 토큰을 받는 것을 확인했다(#28 PR).
4. `at_hash`는 넣지 않는다. EdDSA에 대한 `at_hash` 계산법이 표준에 없고, 코드 플로우에서는 선택이다.
5. 로그인 정보 스코프는 기밀 클라이언트만 요청할 수 있다(공개 클라이언트·DCR·CIMD는 지금처럼 리소스 스코프만).
6. 클레임은 지어내지 않는다: `name`은 대표 이름이 있을 때만, `email`·`email_verified`는 이메일이 있을 때만(`owner set-email`·`set-name`).

## 결과

- discovery(`/.well-known/openid-configuration`)와 RFC 8414 문서는 한 함수가 만드는 같은 문서다.
- 리프레시하면 ID 토큰을 다시 낸다(`auth_time`은 처음 로그인 시각, `nonce` 없음 — OIDC Core 12.2). 그래서 리프레시 토큰이 `auth_time`을 기억한다.
- RS256만 받는 RP가 생기면 그때 ID 토큰 전용 RSA 키(별도 `SigningKey` 종류, JWKS에 `alg=RS256`)를 더한다. 이 ADR을 고쳐 적는다.
- 로그아웃 전파(RP-initiated logout), 다중 사용자, 그룹 클레임은 범위 밖이다.
