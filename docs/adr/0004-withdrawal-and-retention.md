# 0004. 탈퇴: 즉시 비활성, `user.deleted` 웹훅, 30일 뒤 개인정보 삭제

- 상태: 채택 (2026-10-24, #39, 스펙 #34 결정 8)

## 배경

일반 사용자(ADR 0003)는 「내 계정」에서 스스로 탈퇴할 수 있어야 한다. 스펙 #34 결정 8은 「탈퇴 즉시 비활성화, 연결된 앱에 서명된 `user.deleted` 웹훅, auth의 개인정보는 30일 유예 뒤 삭제」다. 약관 문서(`sandcorporation/privacy-and-terms`)는 이미 「탈퇴 30일 뒤 이메일·이름·외부 신원 삭제, 약관 동의 기록도 함께, 감사 기록은 1년 보관」이라고 적었으므로 코드는 그보다 늦게 지우면 안 된다(더 일찍 지우는 것은 괜찮다).

## 결정

1. **탈퇴는 확인 문구 입력으로 한다.** `/account/withdraw`(일반 사용자만, 대표는 403)에서 「탈퇴합니다」를 정확히 입력해야 한다. 틀리면 400과 같은 화면. 대표 계정은 탈퇴가 없다(`manage.py owner`로만 관리).
2. **탈퇴는 한 트랜잭션에서 즉시 다음을 한다**(`services/withdrawal.py` `withdraw_member`):
   - `User.is_active=False`, `Member.status="withdrawn"`, `Member.withdrawn_at`. 두 번 눌러도 한 번만 된다(조건부 update로 선점).
   - 로그인·`/authorize`·`/token`(코드 교환·리프레시)·`/userinfo`가 모두 거절된다. 규칙은 `check_member_grant`의 첫 줄(`MemberInactive`, DB에서 다시 읽는다)이라 세 자리(`/authorize`·`/token`·토큰 생성기)가 함께 막힌다. 리프레시 회전은 잠근 행에서 패밀리 철회도 다시 본다.
   - 지금 세션은 로그아웃하고, 다른 기기 세션은 Django `ModelBackend`가 비활성 사용자를 버리므로 다음 요청부터 로그인이 풀린다.
   - 모든 동의를 철회하고(`revoke_consent`, 사유 `member_withdrawn`) 남은 리프레시 토큰 패밀리도 철회한다.
   - **외부 신원(`ExternalIdentity`) 행을 지운다.** (provider, provider_sub) 유일 제약 때문에 남겨 두면 같은 소셜 계정으로 다시 가입할 수 없다. 묘비 계정으로 바꿔 두는 방법 대신 지우기를 고른 까닭: 약관상 30일 안에 어차피 지울 개인정보이고, 일찍 지워도 문제가 없으며, 「이 소셜 계정은 탈퇴한 계정이었다」를 기억할 필요가 없다(복구도 안내도 하지 않으므로).
   - 그 사용자(`actor = sub`)의 감사 기록에서 IP를 지운다(익명화).
   - 그 사용자가 **한 번이라도 동의한** 클라이언트(철회 전에 뽑는다) 중 웹훅이 있는 곳마다 `user.deleted` 전송 행을 대기열에 넣는다.
3. **30일 유예 동안 복구는 없다.** 같은 Google·Kakao 계정으로 다시 오면 **새 계정**(새 `sub`, 「동의 대기」부터)이 된다. 「이전에 가입한 계정이 있다」는 안내는 하지 않는다 — 탈퇴 계정은 같은 이메일 안내(`providers_with_email`)에서도 빠진다. 탈퇴 계정의 이메일은 다른 사용자가 쓸 수 있다.
4. **30일 뒤 삭제**(`manage.py members purge`, 하루 한 번): `withdrawn_at + 30일 ≤ 지금`인 탈퇴 계정에서 아래를 지우고 `Member.purged_at`을 적는다. 29일 23시 59분에는 남고 30일 0분에 지워진다.

   | 30일 뒤 지우는 것 | 묘비로 남는 것 |
   |---|---|
   | 계정 이메일(`User.email`), 이름(`first_name`·`last_name`), 이메일 확인 여부 | `sub`(`User.username`) — 재사용 방지 |
   | 남은 외부 신원(탈퇴 때 이미 지움) | 상태 「탈퇴」, `is_active=False` |
   | 약관 동의 기록(`TermsAgreement`) | 탈퇴 시각(`withdrawn_at`), 삭제 시각(`purged_at`), 가입 시각(`created_at`·`date_joined`) |
   | 앱 동의(`Consent`)와 거기 딸린 코드·리프레시 토큰 | — |

   `User` 행은 지우지 않는다. 지우면 username이 풀려 같은 `sub`가 다시 생길 수 있고(ULID라 사실상 없지만 규칙으로 막는다), 사이트가 들고 있는 `sub`가 무엇이었는지 설명할 근거가 사라진다.
5. **보유 기간이 끝난 기록도 같은 명령이 지운다.**
   - 감사 기록: 생성(`at`)부터 1년(365일)이 지나면 지운다(대표 포함 전체).
   - 끝난(성공 또는 포기) 웹훅 전송 행: 만든 지 30일 지나면 지운다(본문에 `sub`가 있다).
   - 요청 제한 카운터(`ThrottleCounter`, 키에 IP가 있다): 하루 넘게 쉰 행(창·차단이 모두 끝남)을 지운다. 모든 규칙의 창·차단이 1시간 이하라 판단이 바뀌지 않는다.
6. **웹훅.**
   - 클라이언트에 `webhook_url`(https만)과 서명 비밀을 둔다. 비밀은 32바이트 난수의 hex 64자이고, HMAC에 원문이 필요하므로 해시가 아니라 `SIGNING_KEY_ENCRYPTION_KEY`(Fernet, `services/crypto.py`)로 암호화해 저장한다. 발급 때 한 번만 보인다(`clients webhook`, admin). 웹훅 URL은 운영자가 정하는 값이라 CIMD처럼 주소 고정(사설 주소 차단)은 하지 않는다. 리다이렉트는 따라가지 않는다.
   - 본문 `{"id": <ULID>, "type": "user.deleted", "sub": "...", "occurred_at": "<ISO 8601 UTC>"}`, 헤더 `X-Sandcorp-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`, `X-Sandcorp-Event`, `X-Sandcorp-Delivery`(= `id`). 받는 쪽 검증은 `docs/resource-server-token-validation.md` 11절(5분 창, `id` 중복 무시).
   - **요청 안에서 보내지 않는다.** 탈퇴 트랜잭션은 `WebhookDelivery` 행만 남기고, 전송기 `manage.py webhooks deliver`(5분마다)가 보낸다. 행은 조건부 update로 선점(10분 임대)하므로 전송기가 겹쳐 돌아도 한 번만 보낸다.
   - 2xx면 끝. 그 밖은 실패 뒤 5분·15분·1시간·3시간·6시간·12시간·24시간 뒤 다시 보내고(최대 8번, 약 2일), 8번째도 실패하면 포기(`gave_up_at`)한다. 포기한 전송은 `webhooks list`에 보인다. 본문과 `id`는 시도마다 같고 서명(`t`)만 새로 만든다.
7. **주기 실행.** 저장소에 주기 작업 관례가 없어서(Jenkins는 push 때 배포만) 운영 호스트의 cron으로 돌린다(`docs/operations.md` 11절): 5분마다 `webhooks deliver`, 하루 한 번 `members purge`.

## 결과

- 이미 발급된 액세스 토큰은 만료(최대 10분)까지 서명상 유효하다. 사이트는 웹훅을 받아 그 `sub`를 정리하고, 리프레시 실패(`invalid_grant`)를 로그아웃으로 다룬다.
- 웹훅 비밀은 `SIGNING_KEY_ENCRYPTION_KEY`에 묶인다. 그 키를 바꾸면 서명 키·TOTP 비밀과 함께 웹훅 비밀도 다시 발급해야 한다.
- 탈퇴 계정 행은 영구히 남는다(개인정보 없는 묘비). 수가 늘어도 행 크기가 작아 문제 삼지 않는다.
- IP 익명화는 감사 기록의 `ip` 칼럼만 지운다. `detail`에 IP를 넣는 기록 종류를 새로 만들면 이 규칙도 함께 고친다.
