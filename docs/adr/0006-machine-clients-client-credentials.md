# 0006. 서비스 간 호출은 client_credentials 기계 클라이언트로, 표시는 `acct=machine`

- 상태: 채택 (2026-11-06, #76)

## 배경

promptlab의 Windows 끝에서 끝 스모크(Jenkins Windows 노드)가 사람 로그인 없이 운영 promptlab(리소스 `https://promptlab.sandcorp.co.kr/api`)에 응시·제출해야 한다. 지금까지 `/token`은 사람(대표·일반 사용자)의 동의에서 나온 코드·refresh token만 받았고 `client_credentials`는 거절했다. 대표 결정(2026-11-06): client_credentials 기계 클라이언트, 스모크는 운영의 시험 전용 조직에서만 제출.

## 결정

1. **클라이언트 종류 `machine`을 더한다.** 관리 명령 `clients create-machine`으로만 만들고(DCR·CIMD·admin 추가 화면 없음), 리소스 하나(`machine_resource`)와 그 리소스의 스코프 이름 목록(`machine_scopes`)에 묶는다. 시크릿 규칙은 기밀 클라이언트와 같다(한 번만 출력, 해시 저장, `rotate-secret`).
2. **`grant_type=client_credentials`는 기계 클라이언트에만 연다**(`Client.check_grant_type`). 기계 클라이언트는 그 밖의 그랜트와 `/authorize`를 쓰지 못한다. 공개·동적·CIMD·기밀 클라이언트의 거절은 그대로다. 발급은 묶인 리소스·스코프 안에서만, 사용자 없음, refresh token 없음, 수명은 다른 액세스 토큰과 같은 10분.
3. **사람과 기계의 구분은 기존 계정 종류 클레임 `acct`에 값 `"machine"`을 더해서 한다.** `sub`는 `client:<client_id>`(대표 username·`m_` + ULID와 겹치지 않는다). 새 클레임(`client_kind` 등)을 만들지 않은 까닭: 지금 사이트들의 검증 규칙이 이 토큰을 **고치지 않아도** 거부한다 — 대표 전용 사이트는 T11(`sub` ≠ 대표), 일반 사용자를 받는 사이트는 A2(`acct` ≠ `"member"`)에 걸린다. 새 클레임이면 그것을 모르는 사이트가 `sub`만 보고 판단할 여지가 남는다.
4. 기계 토큰을 받는 자리는 검증 규칙 M1~M3(`docs/resource-server-token-validation.md` 12절)을 따르고, 받을 `client_id` 목록을 사이트 설정으로 둔다. 그 클라이언트가 무엇을 할 수 있는지는 사이트가 정한다.

## 검토한 대안

- **대표 계정의 장기 refresh token을 스모크에 심기**: 사람의 권한 전체가 CI 노드에 놓인다. 기계 클라이언트는 리소스·스코프 하나로 좁고, 끊어도 대표 로그인에 영향이 없다.
- **`client_kind` 같은 새 클레임**: 3번의 까닭으로 고르지 않았다.
- **기밀 클라이언트에 client_credentials를 함께 열기**: 사이트 관리 화면 로그인용 시크릿이 사람 없이 토큰을 받는 데까지 쓰이게 된다. 용도를 갈라 둔다.

## 결과

- 리소스 서버 쪽 공용 패키지 `sandcorp-authkit`에는 아직 기계 토큰 검증 함수가 없다. 처음 쓰는 사이트(promptlab) 쪽 티켓에서 더한다.
