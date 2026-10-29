# 자원 서버가 sandcorp-authkit을 쓰는 법

자원 서버(portfolio, metrics, news, flow)는 토큰 검증·메타데이터·bearer 인증·운영자 로그인을 직접 구현하지 않고 공용 패키지 `sandcorp-authkit`(`clients/python/`)을 쓴다. 결정 배경은 [ADR 0005](adr/0005-resource-server-authkit.md), 규칙의 원문은 [resource-server-token-validation.md](resource-server-token-validation.md), 공개 API는 [clients/python/README.md](../clients/python/README.md). 스펙은 #54.

저장소에 남는 인증 코드는 **어댑터 한 파일**뿐이다. settings를 읽는 곳도 거기 하나다.

## 1. 의존성 추가

저장소가 private이므로 주소는 **ssh**다(https 줄은 쓰지 않는다). 태그를 고정한다.

uv 저장소(metrics·portfolio·news):

```toml
[project]
dependencies = ["sandcorp-authkit[django]"]

[tool.uv.sources]
sandcorp-authkit = { git = "ssh://git@github.com/sandcorporation/sandcorp-auth.git", subdirectory = "clients/python", tag = "authkit-v0.2.0" }
```

`uv lock`은 `--upgrade` 없이 돌린다(다른 패키지가 같이 올라가지 않게).

pip 저장소(flow: `backend/requirements.txt`, uv 안 씀):

```
sandcorp-authkit[django] @ git+ssh://git@github.com/sandcorporation/sandcorp-auth.git@authkit-v0.2.0#subdirectory=clients/python
```

요구: Python 3.14 이상, Django ≥ 6.1, django-ninja ≥ 1.7(extra `django`일 때). 의존성은 `pyjwt[crypto]`뿐.

## 2. 어댑터 한 파일

settings → `BearerConfig`/`LoginConfig`·`jwks_cache`·`token_transport`·`clock`, ninja `admin_auth`, MCP 뷰용 `require_admin`, `protected_resource_metadata`를 만든다. 패키지는 settings·환경 변수를 읽지 않는다. 꼴과 예시는 README 「저장소에서 쓰는 법 — 어댑터 한 파일」, 시험 fake 대응은 「저장소 fake → 패키지」. 규칙:

- `sandcorp_authkit.django`는 Django settings가 구성된 뒤에 import한다(ninja가 import 때 settings를 읽는다).
- 사이트 몫(로그인 `next` 안전 검사, 대표 Django 사용자 만들기·되살리기·비활성 거절, 오류 화면)은 저장소에 남긴다. 패키지가 대신하지 않는다(metrics `oauth/admin_login.py`).
- flow 고유 규칙은 훅으로: `acct`·member sub는 `extra_claims_hook=owner_or_member(owner_sub)`, `/mcp` 메타데이터 경로는 `metadata_path(resource)`.
- 패키지는 오류 본문을 `{"error": …}`로 통일한다. 저장소가 기존 응답 꼴(`{"detail": …}` 등)을 유지해야 하면 어댑터에서 감싼다.
- 시험은 `sandcorp_authkit.testing`(`FakeJwks`·`FakeTokenEndpoint`·`FixedClock`). 저장소 conftest에는 settings 픽스처·seam monkeypatch·토큰 기본값만 둔다.

### 저장소별 어댑터 위치

| 저장소 | 어댑터 | 비고 |
|---|---|---|
| sandcorp-metrics | `backend/oauth/auth.py` | 운영자 로그인 뷰 `oauth/admin_login.py`(사이트 몫) — #15 |
| portfolio | `backend/oauth/auth.py` | #142 |
| AI-Trend-News | `backend/core/auth_adapter.py` | #111 |
| sandcorp-flow | #282 본문 기준: settings → `BearerConfig`/`LoginConfig`를 만드는 어댑터 한 파일. 경로는 **병합 뒤 확인** | 지우는 쪽은 `apps/tenants/resource_token.py`·`operator_login.py`. 병합은 secret 등록 뒤 |

## 3. Docker 빌드: 키를 이미지에 남기지 않고 private 저장소 받기

공통: BuildKit SSH 전달. 빌드 단계에서만 `RUN --mount=type=ssh`로 에이전트를 쓰고, 키·`known_hosts`·`git`·`ssh`는 최종(runtime) 이미지에 들어가지 않게 한다(의존성을 설치하는 pydeps 단계에서만 쓰고 runtime은 `/opt/venv`만 복사). 키 내용·경로는 로그에 찍지 않는다. 확인: `docker history --no-trunc <이미지>`에 `PRIVATE KEY`·`ssh-rsa`·`known_hosts`가 없고, runtime에 `/root/.ssh`가 없다.

### 3-1. Jenkins / oracle 변형 (metrics #15 기준)

자원 서버 잡은 oracle 에이전트(컨테이너, SSH 키 없음)에서 `deploy/deploy.sh`의 `docker compose build`(BuildKit, compose `--ssh` 지원)로 빌드한다. 자격은 Jenkins SCM 자격 `github-farrar142`(SSH 키, sandcorp-auth 읽기 권한).

- **Dockerfile** pydeps 단계: `git`·`openssh-client` 설치, `mkdir -p -m 0700 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts`, `RUN --mount=type=ssh uv sync …`.
- **Jenkinsfile**: `withCredentials([sshUserPrivateKey(credentialsId: 'github-farrar142', keyFileVariable: 'GIT_SSH_KEY')])`로 빌드·배포 단계를 감싼다.
- **deploy/deploy.sh**: `GIT_SSH_KEY`가 있으면 임시 `ssh-agent`에 `ssh-add`하고 `docker compose build --ssh default web`, 끝에 `ssh-agent -k`(`trap`). 없으면 개발자 agent를 쓴다.
- 로컬 확인: `docker compose build --ssh default[=~/.ssh/키] web`.

### 3-2. GitHub Actions 변형 (flow #282 기준)

flow는 이미지를 Jenkins가 아니라 GitHub Actions(`.github/workflows/build-images.yml`, self-hosted `arm64-builder`)가 빌드해 GHCR에 push한다. Jenkins 잡(인라인 Execute shell)과 `scripts/deploy.sh`는 pull·migrate·rollout만 하므로 바꾸지 않는다. `GITHUB_TOKEN`은 다른 private 저장소를 읽지 못하므로 키를 따로 둔다.

- **secret `AUTHKIT_SSH_KEY`**: ed25519 개인키. 짝인 공개키를 sandcorp-auth의 **읽기 전용 deploy key**로 등록한다. secret은 사용자가 등록한다 — 등록 전에 병합하면 빌드가 깨진다.
- **워크플로**: api 이미지 빌드 앞에 ssh-agent 단계(secret을 `ssh-add`, github.com을 known_hosts에), `docker/build-push-action`에 `ssh: default`. admin·widget 빌드는 바꾸지 않는다.
- **Dockerfile**: pip라서 `RUN --mount=type=ssh pip install --no-cache-dir -r requirements.txt`(앞에 `git`·`openssh-client`·`ssh-keyscan`). `Dockerfile.test`와 `docker-compose.test.yml`은 build에 `ssh: [default]`를 넣어 개발자 ssh-agent로 받는다.
- 병합 뒤: build-images(api) success 확인(깨지면 secret 문제), 그다음 Jenkins 배포.

## 4. 운영 확인 체크리스트

병합·배포 뒤 저장소마다 확인한다(Jenkins 빌드 SUCCESS가 먼저).

1. 메타데이터 200: `GET <자원>/.well-known/oauth-protected-resource`. 자원에 경로가 있으면 RFC 9728대로 `/.well-known/oauth-protected-resource<경로>`(flow는 `…/oauth-protected-resource/mcp`).
2. 엉터리 Bearer로 보호 경로 호출 → 401 + `WWW-Authenticate: Bearer resource_metadata="…"`.
3. 운영자 로그인 시작 → 302, auth 서버 `/authorize` URL에 `state`·`nonce`·`code_challenge`(S256)·`resource`.
4. 운영 로그에서 401 급증이 없는지 10분 관찰한다(검증이 이전보다 엄격해진 곳이 있다 — ADR 0005 「결과」). 실제 클라이언트(claude.ai 커넥터 등) 호출이 계속되는지.

## 5. 버전 올리기

1. 이 저장소에서 패키지를 고치고 `clients/python/pyproject.toml` 버전을 올려 PR → 병합.
2. 태그 `authkit-vX.Y.Z`를 **병합 커밋**에 건다(자세한 것은 `clients/python/README.md` 「버전」).
3. 자원 서버마다 **PR 하나씩**: `pyproject.toml`의 `tag`(flow는 `requirements.txt`의 `@authkit-v…`)만 올리고 `uv lock`(`--upgrade` 없이). 표의 어댑터와 시험이 그대로 통과해야 한다.
4. 규칙·발급 claim을 바꾸는 변경은 [resource-server-token-validation.md](resource-server-token-validation.md)와 패키지를 같은 PR에서 함께 고친다. 응답이 바뀌면 각 PR 본문에 「바뀐 동작」 표를 적는다.
