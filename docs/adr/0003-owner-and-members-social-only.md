# 0003. 단일 대표 → 대표 + 일반 사용자, 소셜 로그인 전용

- 상태: 채택 (2026-10-24, #35, 스펙 #34)

## 배경

sandcorp-auth는 대표 한 명만 쓰는 인증 서비스였고, 사이트(portfolio, Foresight, metrics, MCP)는 검증 규칙 T11(`sub == AUTH_OWNER_SUB`)로 대표만 받는다. Sandcorp Flow(셀프 가입 SaaS)를 시작으로 일반 사용자를 받는 앱이 늘어나므로, 앱마다 계정을 두지 않고 auth가 하나의 「Sandcorp 계정」으로 통합 인증한다(사용자 결정 10개, #34). 가입은 Google·Kakao 소셜 로그인만 받고 비밀번호와 메일은 다루지 않는다. 앱별 권한(테넌트·역할·초대)은 각 앱이 `sub`를 키로 관리한다.

## 결정

1. **계정 종류는 둘이다.** 대표(owner)는 지금 그대로(비밀번호+TOTP, `sub=farrar142`, `manage.py owner`). 일반 사용자(member)는 Django `User` + `accounts.Member` 행이다. `Member` 행이 없는 유일한 `User`가 대표이고, `Member` 행이 있는 `User`는 몇이든 된다(「계정 하나뿐」 신호는 대표에게만 건다). member는 쓸 수 있는 비밀번호가 없고 staff·superuser가 아니며 TOTP를 거치지 않는다.
2. **member `sub`는 `m_` + ULID 26자**(Crockford base32 대문자, 정규식 `m_[0-7][0-9A-HJKMNP-TV-Z]{25}`, 앞 48비트 가입 시각 ms + 80비트 난수). `User.username`이 곧 `sub`이고 바뀌지 않는다. 이름·이메일·제공자 ID로 만들지 않는다. 대표 username은 `m_`로 시작할 수 없다. 접두사 덕에 대표 `sub`와 겹칠 수 없고, 사이트가 형식만으로 member 토큰의 `sub`를 거를 수 있다.
3. **외부 신원 `accounts.ExternalIdentity`**: `provider`(google|kakao)·제공자 `sub`·이메일(선택)·이메일 검증 여부·표시 이름·연결 시각. (provider, 제공자 sub)는 유일하고 한 계정에 여러 신원이 붙을 수 있다. 자동 병합은 없다 — 처음 들어온 수단마다 새 계정이다(`services.members.create_member`, 이미 연결된 신원이면 `IdentityTaken`).
4. **계정 종류 클레임 `acct`**: member의 액세스 토큰·ID 토큰·userinfo에 `"acct": "member"`. **대표 토큰에는 `acct`가 없다.** 대표 토큰을 한 글자도 바꾸지 않아 기존 사이트와 기존 시험이 그대로 서고, member를 받는 사이트는 「`acct` 없음 = 대표」로 읽는다(`docs/resource-server-token-validation.md` 10절). discovery `claims_supported`에는 올리지 않는다(Sandcorp 전용 클레임, 계약은 그 문서).
5. **member가 받을 수 있는 스코프는 `login`·`openid`·`profile`·`email`뿐**(`services.members.MEMBER_SCOPES`). `admin`·`editor`를 비롯한 다른 리소스 스코프를 요청하면 빼지 않고 **거부**한다(`/authorize`가 `error=invalid_scope`로 돌려보냄). 조용히 빼면 클라이언트가 기대와 다른 토큰을 받는다.
   - **보충(#47, 2026-10-24)**: 리소스가 자기 스코프 일부를 member에게 열 수 있다. `Scope.members_allowed`(기본 꺼짐)가 켜진 스코프는 **그 리소스를 요청했을 때만** member 허용 집합에 들어간다(`services.members.member_scopes`; 다른 리소스의 같은 이름은 세지 않는다). `admin`·`editor`는 모델 `clean`·DB 체크 제약·`scopes members` 명령에서 켤 수 없다. 첫 사례는 Flow 테넌트용 MCP의 `flow.read`·`flow.write` — 실제 쓰기 권한(테넌트 Admin)은 Flow가 멤버십으로 판정하므로, auth는 「서명해 줄 수 있다」만 안다. 코드 상수로 두면 사이트가 늘 때마다 auth 배포가 필요해 데이터 표시로 옮겼다. 세 겹(7)은 그대로 이 집합으로 판정한다.
6. **클라이언트 「일반 사용자 허용」(`Client.allows_members`, 기본 꺼짐).** 꺼진 클라이언트의 `/authorize`에 member 세션이 오면 동의·코드 없이 `error=access_denied`로 돌려보낸다(리다이렉트 URI가 검증된 뒤라 클라이언트로 돌아간다). admin 클라이언트 화면과 `manage.py clients members --client-id <id> --allow|--deny`(`create-confidential --allow-members`)로 켜고 끈다(감사 `client.members_changed`).
7. **세 겹으로 막는다.** `/authorize`(5·6), `/token`(코드 교환·리프레시 때 같은 규칙을 다시 — 그 사이 표시를 끄면 `invalid_grant`), 토큰 생성기(`SandcorpTokenGenerator`, 어겨지면 서명하지 않고 예외). 그리고 기존 사이트는 T11로 member를 또 거른다.
8. **member userinfo·ID 토큰**: `sub`, `acct`, `name`(표시 이름이 있을 때, `profile`), `email`·`email_verified`(이메일이 있을 때만, `email`; `email_verified`는 member 자신의 값 — 이메일이 없으면 두 클레임 모두 없다 — Kakao는 codemit과 같은 비즈 앱을 공유해 이메일을 필수 동의로 받지만(2026-10-24 결정, `docs/operations.md` 9절), 이메일이 없는 카카오 계정은 여전히 이메일 없이 들어온다). `preferred_username`은 주지 않는다(username이 불투명한 `sub`라서).

## 결과

- 기존 사이트 3곳과 MCP의 토큰·규칙·클라이언트는 그대로다. 그 클라이언트들은 「일반 사용자 허용」이 꺼져 있어 member 토큰을 받을 길이 없다.
- 로그인 흐름(Google·Kakao 어댑터, 같은 이메일 안내)은 #36, 약관은 #38, 화면·내 계정은 #37, 탈퇴(`is_active=False`, 웹훅, 30일 삭제)는 #39가 이 모델 위에 얹는다.
- 대표가 소셜 신원을 붙이는 일은 정하지 않았다(지금은 member만 신원을 가진다).
