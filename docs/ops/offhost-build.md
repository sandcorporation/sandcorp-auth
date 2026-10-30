# 이미지를 oracle 밖에서 굽기 (#68)

oracle(aarch64, 4코어)은 운영 서비스 열 개 남짓이 CPU를 나눠 쓴다. 배포할 때마다 거기서 이미지를 빌드하면 운영 서비스가 느려진다.
그래서 **이미지는 다른 노드에서 굽고 ghcr에 올리며, oracle은 받아서 교체만 한다.** news(AI-Trend-News #142)가 첫 사례이고 이 저장소는 그 패턴을 그대로 옮겼다(패턴 원문: AI-Trend-News `docs/ops/offhost-build.md`).

## 흐름

```
main push ─▶ 이미지 빌드 ─────────────────────▶ 배포(oracle)
             macos (M4 Pro, arm64 네이티브)       docker pull ghcr.io/sandcorporation/sandcorp-auth:<sha>
             └ 3분 안에 실행기를 못 잡으면        wait_for_db → migrate → web·scheduler 교체 → 헬스 확인
               sub(built-in, QEMU로 arm64)         (빌드 없음)
```

- **노드를 못 잡았을 때만** sub로 넘어간다. macos에서 빌드가 실패하면 실패로 끝낸다(다시 sub로 굽지 않는다).
- 빌드 노드는 콘솔(`== 빌드 노드: macos (...)`)과 빌드 설명(`<sha12> · 빌드 macos · oracle pull`)·디스코드 알림에 남는다.
- 이미지: `ghcr.io/sandcorporation/sandcorp-auth:<커밋 sha 40자>`, 레이블 `org.opencontainers.image.source`·`revision`. 빌드 캐시는 `sandcorp-auth-buildcache:arm64`(레지스트리, `mode=max`).
- 자격: ghcr 쓰기 `ghcr-push-token`(Secret text, codemit과 공유), 이 저장소는 비공개 의존성을 이미지에 넣지 않아(`clients`는 `.dockerignore`) SSH 키가 필요 없다. oracle은 호스트 docker 설정에 있는 ghcr **읽기** 로그인을 쓴다(sandcorp-flow와 같다).

## 파라미터

| 이름 | 기본 | 뜻 |
|---|---|---|
| `BUILDER` | `auto` | `auto` / `macos` / `sub` — 시험용으로 빌드 노드를 강제 |
| `MAC_WAIT_SECONDS` | `180` | auto에서 macos 실행기를 기다리는 시간. 넘으면 sub |
| `ROLLBACK_SHA` | 빈 값 | 채우면 빌드 없이 그 커밋의 이미지로 되돌린다 |

## 이전 sha로 되돌리기

Jenkins `sandcorp-auth`를 「Build with Parameters」로 `ROLLBACK_SHA=<되돌릴 커밋 sha 40자>`를 넣고 돌린다. 빌드 단계는 건너뛰고 oracle이 그 sha 이미지를 pull해 같은 migrate·교체·헬스 절차를 밟는다.
- ghcr에 그 sha 이미지가 있어야 한다(정리 잡 `ghcr-prune`이 오래된 것을 지운다).
- migrate는 앞으로만 간다. 되돌리는 코드가 새 스키마를 못 읽으면 DB를 따로 되돌려야 한다(파괴적 스키마 변경은 두 번에 나눠 배포하는 규칙 그대로).

## 이 저장소의 사정

- 이미지 변수는 `AUTH_IMAGE`(compose `image: ${AUTH_IMAGE:-sandcorp-auth-web:latest}`). 로컬 `make prod-local`은 변수가 없어 빌드한다.
- 스크립트 `scripts/ci/build-image.sh`, 환경 `AUTH_IMAGE_REPO`·`AUTH_BUILDER`(`auth-images` 빌더).
- 운영 `.env`·NPMplus·DB는 그대로다. 손으로 `docker compose up`을 하면 `AUTH_IMAGE`가 없어 로컬 이름의 이미지를 찾으니, 운영에서 web을 다시 띄울 때는 Jenkins를 돌리거나 `AUTH_IMAGE=ghcr.io/sandcorporation/sandcorp-auth:<sha> docker compose … up -d --no-build --no-deps --force-recreate web`로 한다.
- Jenkins 잡 `sandcorp-auth`는 노드 `macos`·`laurio-staging`(sub)·`oracle`을 쓰고 자격증명 `ghcr-push-token`, `discord-deploy-webhook`을 이름으로 부른다.
- 노드 대기 시간 제한은 `parallel(failFast)` + `sleep` 감시다. `Jenkins.instance` 같은 스크립트 승인 API는 쓰지 않는다.
- oracle 호스트의 docker가 `ghcr.io`에 읽기 로그인돼 있어야 한다. 패키지가 새로 만들어지면 ghcr에서 이 저장소에 접근 권한이 있는지 본다.
