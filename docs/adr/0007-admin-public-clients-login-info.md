# 0007. PC에서 도는 프로그램의 OIDC 로그인은 관리자가 만든 공개 클라이언트 + 「로그인 정보 허용」 표시로

- 상태: 채택 (2026-11-19, #102)

## 배경

자기 PC에 깔아 loopback(`http://127.0.0.1:<포트>`)에서만 도는 웹 프로그램이 이 서비스로 OIDC 로그인을 할 수 없었다. 로그인 정보 스코프(`openid`·`profile`·`email`)는 기밀 클라이언트에만 주고, 기밀 클라이언트의 redirect URI는 https만 받기 때문이다. 대표 결정: 관리자가 직접 만든 클라이언트에만 허용하고, 누구나 스스로 등록하는 클라이언트(DCR·CIMD)는 지금처럼 막는다.

## 결정

1. **관리자가 만드는 공개 클라이언트**를 더한다: `manage.py clients create-public --name … --redirect-uri … [--login-info] [--allow-members]`. 시크릿 없음(`token_endpoint_auth_method=none`), PKCE S256 필수(기존 공개 클라이언트 규칙 그대로), `registered_via=admin`. admin 「추가」 화면은 그대로 기밀 전용이다.
2. **「로그인 정보 허용」 표시 `Client.allows_login_info`**(기본 꺼짐, 만들 때만 정함 — admin에서는 읽기 전용). 표시가 켜진 공개 클라이언트만 로그인 정보 스코프를 받는다(`oauth.grants.requested_scopes`, `Client.public_login_info`). DB 검사 제약 `oauth_client_login_info_admin_public_only`가 「표시가 켜졌으면 `kind=public`·`registered_via=admin`」을 지켜, DCR·CIMD 행에는 켤 수 없다.
3. **redirect URI는 `http://127.0.0.1:<포트>/…` 또는 `http://[::1]:<포트>/…`만, 포트까지 정확히 일치**(`services.redirect_uris.exact_loopback_redirect_uri`, `Client.check_redirect_uri`). `localhost`는 받지 않는다(RFC 8252 §8.3: 이름 풀이가 바뀌거나 방화벽 규칙이 IP와 다를 수 있다). DCR·CIMD 공개 클라이언트의 「loopback 포트 무시」(RFC 8252 §7.3)는 이 표시가 켜진 클라이언트에는 적용하지 않는다 — 고정 포트에서 도는 프로그램이 대상이고, 다른 포트를 잡은 프로그램이 같은 `client_id`로 코드를 받는 길을 하나 줄인다.
4. **표시가 켜진 클라이언트는 `/authorize`마다 동의 화면을 띄운다**(RFC 8252 §8.6). 남아 있는 동의가 스코프를 덮어도 코드를 바로 내주지 않는다. 공개 클라이언트는 `client_id`가 비밀이 아니므로, 같은 PC의 다른 프로그램이 그 `client_id`로 흐름을 시작해도 대표가 버튼을 누르기 전에는 신원 정보가 나가지 않게 한다.
5. 대표 전용(`allows_members` 기본 꺼짐), 일반 사용자 규칙, 약관, step-up, 감사(`client.created`에 `kind`·`login_info`)는 다른 클라이언트와 같다.

## 검토한 대안

- **기밀 클라이언트에 loopback http redirect 허용**: PC에 깔리는 프로그램은 시크릿을 지킬 수 없다(설치 파일·설정 파일에서 꺼낼 수 있다). 시크릿이 「이 클라이언트다」를 증명한다는 기밀 클라이언트의 전제가 깨지고, 그 시크릿이 새면 https 사이트용 기밀 클라이언트와 같은 무게로 읽힌다. RFC 8252가 네이티브 앱을 공개 클라이언트로 두는 까닭과 같다.
- **DCR 클라이언트에도 표시를 켤 수 있게**: 누구나 등록할 수 있어 대표 결정에 어긋난다.
- **loopback 포트 무시 유지**: 프로그램이 로그인마다 포트를 바꾸는 경우엔 편하지만, 이 용도(고정 포트 웹 프로그램)에는 필요 없고 열린 쪽이다.

## 위험(남는 것)

- **같은 PC의 다른 프로그램이 등록한 포트를 먼저 잡는 경우**: 진짜 프로그램이 꺼져 있을 때 악성 프로그램이 그 포트에서 듣고 `client_id`로 흐름을 시작하면, 대표가 동의 화면에서 「허용」을 누를 때 코드가 그 프로그램으로 간다. PKCE는 흐름을 시작한 쪽이 verifier를 가지므로 이것을 막지 못한다. 막는 것은 매번 뜨는 동의 화면(4번)뿐이다 — 대표가 시작하지 않은 로그인의 동의 화면은 허용하지 않는다. 같은 PC에 악성 프로그램이 이미 있다면 브라우저 세션 자체도 위험하므로, 이 위험은 PC의 신뢰에 묶인다.
- 표시가 켜진 클라이언트의 refresh token은 다른 공개 클라이언트와 같은 규칙(회전, 재사용 탐지)이다. 프로그램이 refresh token을 디스크에 두면 그 PC의 다른 프로그램이 읽을 수 있다.
- 끄기는 admin 「비활성」(클라이언트 폐기)이다. 표시만 끄는 명령은 두지 않았다 — 필요하면 비활성 후 다시 만든다.
