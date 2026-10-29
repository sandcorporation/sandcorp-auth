# 0005. 자원 서버 인증 코드는 공용 패키지로, 인증 서버는 둘 유지

- 상태: 채택 (2026-10-29, #54, T7 #62)

## 배경

MCP를 쓰는 자원 서버 넷(portfolio, metrics, news, flow)이 같은 일을 각자 구현했다: 토큰 검증(EdDSA JWT, JWKS 캐시), `/.well-known/oauth-protected-resource` 메타데이터, bearer 인증과 401/403 응답, 운영자 로그인(authorize → PKCE → token 교환 → 세션). portfolio와 metrics는 파일이 거의 같고(차이 16~45줄), news와 flow는 다른 변형이었다. 규칙이 바뀌면 네 곳을 고쳐야 했고 같은 버그가 따로 생겼다.

## 결정

1. **자원 서버 쪽만 공용 패키지로 묶는다.** `sandcorp-authkit`(import `sandcorp_authkit`)을 이 저장소 `clients/python/`에 둔다. 토큰 claim·scope·메타데이터 계약이 여기서 정해지므로 소비 코드도 같은 곳에서 함께 시험한다. 모듈은 `tokens`·`resource`·`django`·`login`·`testing`.
2. **설정은 함수 인자로만 받는다.** 패키지는 settings·환경 변수를 읽지 않는다. 저장소는 어댑터 한 파일에서 값을 넘긴다.
3. **Python 3.14만, 의존성은 `pyjwt[crypto]`뿐**(Django·ninja는 extra). 모든 저장소를 먼저 3.14로 올린다.
4. **배포는 태그 `authkit-vX.Y.Z`의 uv/pip git 의존성**(ssh 주소, private 저장소). 자원 서버는 태그를 고정하고 올릴 때 저장소마다 PR 하나. 빌드 방식은 [resource-servers.md](../resource-servers.md).
5. **인증 서버는 둘 그대로 둔다**: sandcorp-auth와 laurio(classroom.codemit.kr, 자체 인증 서버이자 자원 서버). laurio는 이번에 옮기지 않고, 나중에 자원 서버 쪽만 패키지로 바꾸는 티켓을 따로 낸다. daypage는 MCP가 없어 대상이 아니다.

## 검토한 대안

- **laurio까지 통합(인증 서버 하나로)**: 사용자 결정으로 이번 범위 밖. 계정·클라이언트 이전이 따르는 별도 결정이다.
- **공개 저장소로 분리**: 패키지만 공개하면 설치는 쉽지만 계약(claim·scope)과 소비 코드의 시험이 두 저장소로 갈라진다. 이 저장소 안에 두는 쪽을 골랐고, 대신 private 설치를 위해 SSH 빌드를 감수한다.
- **wheel 배포(레지스트리·릴리스 자산)**: 레지스트리를 따로 운영해야 하고 태그만으로 충분하다고 보아 기각.

## 결과

- 저장소마다 인증 코드는 어댑터 한 파일. 규칙 변경은 패키지 한 곳 + 태그 올리기 PR들.
- 빌드마다 GitHub 읽기 자격이 필요하다(Jenkins/oracle은 `github-farrar142` SSH 키, flow의 GitHub Actions는 deploy key secret `AUTHKIT_SSH_KEY`). 키는 이미지에 남지 않는다.
- **동작이 통일된 것**(저장소마다 달랐던 곳; 이관 PR 본문 「바뀐 동작」 표):
  - 401/403 본문은 `{"error": …}`. 기존 꼴이 필요하면 어댑터가 감싼다.
  - 인증 설정이 없으면 503.
  - 운영자 로그인은 늘 `nonce`를 보내고 id_token의 nonce를 검증한다. 진행 중이던 로그인 1회는 배포 순간 무효.
  - 로그인 시도는 600초에 만료(전에는 세션 수명).
  - `/token` 응답: 리다이렉트를 따르지 않고, `token_type`이 Bearer이며, 액세스 토큰 `client_id`가 이 클라이언트여야 한다. JWKS 응답은 64KB 한도.
  - `iat`·`exp`가 bool이면 거부.
  - JWKS 조회가 실패하거나 이상한 문서면 옛 키를 유지한다.
  - `acct` claim이 있는 토큰(member)은 대표 검증에서 거부한다(대표 토큰엔 원래 없다). 일반 사용자를 받는 flow는 훅으로 받는다.
- 이관 상태: metrics #15, portfolio #142, news #111 병합. flow #282는 진행 중(앞 티켓 #283, 병합은 secret 등록 뒤).
