# 이미지를 oracle 밖에서 굽기 (#68 → #84 Actions·production 승격)

oracle(aarch64, 4코어)은 운영 서비스 열 개 남짓이 CPU를 나눠 쓴다. 배포할 때마다 거기서 이미지를 빌드하면 운영 서비스가 느려진다.
그래서 **이미지는 다른 노드에서 굽고 ghcr에 올리며, oracle은 받아서 교체만 한다.** news(AI-Trend-News #142)가 첫 사례이고 이 저장소는 그 패턴을 그대로 옮겼다(패턴 원문: AI-Trend-News `docs/ops/offhost-build.md`).

## 흐름: Actions가 검사·굽고 production을 승격, Jenkins는 production만 배포 (#84)

```
PR ─▶ pr-check(Actions) ─▶ main 병합
main push ─▶ Actions release.yml
               check   (pr-check.yml을 workflow_call — PR과 같은 린트·타입·시험·승격 스크립트 시험)
               image   needs check — image.yml(workflow_call, ubuntu-24.04-arm matrix) ─▶ ghcr.io/sandcorporation/sandcorp-auth:<sha>
               promote needs check·image — production 브랜치를 <sha>로 fast-forward(GITHUB_TOKEN, contents: write는 이 잡만)
production push(웹훅) ─▶ Jenkins sandcorp-auth(잡 브랜치 */production)
               굽지 않음·검사 없음 → oracle: 이미지가 ghcr에 있는지(상한 5분) → pull → DB 대기 → migrate → web 교체 → 헬스
```

- **production 브랜치 머리 = 운영 버전.** main 검사가 깨지면 이미지도 승격도 없다. 본보기는 sandcorp-metrics(#32·#34, `docs/ops/offhost-build.md`의 「다른 저장소로 펼치기」).
- 승격은 `scripts/ci/promote.sh ff <sha>`: fast-forward만(강제 없음). production이 이미 더 새 판이면(옛 실행이 늦게 끝남) 실패가 아니라 「건너뜀」. concurrency 그룹 `production-branch`로 하나씩. 시험은 `scripts/ci/promote_test.sh`(pr-check가 돌린다).
- GITHUB_TOKEN의 push는 다른 워크플로를 깨우지 않는다. 저장소 웹훅은 깨운다 — Jenkins `githubPush`가 그것을 받는다. main push도 Jenkins를 깨우지만 production이 움직이지 않았으면 「이미 배포에 성공한 sha」로 `NOT_BUILT`.
- Jenkins 쪽 규칙은 jenkins-shared `sandcorpDeploy(deployFrom: 'production')`. 배포 결과는 커밋 상태 `sandcorp/deploy`·실패 PR 댓글·디스코드 `[Auth]`로 남는다. 자동 롤백은 끔(`autoRollback: false`).
- 이미지: `ghcr.io/sandcorporation/sandcorp-auth:<커밋 sha 40자>`, 레이블 `org.opencontainers.image.source`·`revision`, provenance 없음(지금과 같다 — oracle compose는 그대로). 빌드 캐시는 같은 패키지의 `:buildcache` 태그(레지스트리, `mode=max`). 빌드 인자·비밀 없음(`clients`는 `.dockerignore`).
- 보안: `pull_request_target` 없음, GitHub 호스팅 실행기만, 액션 SHA 고정, GITHUB_TOKEN 말고 secrets 없음, 워크플로 기본 권한 없음(잡마다 최소).
- production 브랜치 보호: ruleset(조율자가 건다) — 강제 push·삭제 금지, bypass는 조직 관리자만. **production은 앞으로만 간다.** GitHub Actions 앱을 bypass로 둘 수 없어(422) 「Actions만 push」는 강제할 수 없다 — 사람이 production에 손으로 push하지 않는 것은 약속이다.

## 비상 길: Jenkins가 oracle 밖에서 굽는다 (`BUILD_ON=jenkins`)

Actions가 못 구울 때 Jenkins 「Build with Parameters」에서 `BUILD_ON=jenkins`. 지금 production 머리를 macos(M4 Pro, arm64 네이티브)에서 굽고 — 3분 안에 실행기를 못 잡으면 home(built-in, QEMU) — 배포한다(검사·대기 없음).
- **노드를 못 잡았을 때만** home으로 넘어간다. macos에서 빌드가 실패하면 실패로 끝낸다.
- 스크립트 `scripts/ci/build-image.sh <macos|home>`(Jenkinsfile의 `buildScript`), 캐시 `sandcorp-auth-buildcache:arm64`. 자격: ghcr 쓰기 `ghcr-push-token`. SSH 키는 필요 없다.

## 파라미터

| 이름 | 기본 | 뜻 |
|---|---|---|
| `BUILD_ON` | `actions` | `actions` = Actions가 구워 승격한 production 머리의 이미지를 받아 배포 / `jenkins` = 비상 길(`BUILDER`)로 굽는다 |
| `BUILDER` | `auto` | `auto` / `macos` / `home` — 시험용으로 빌드 노드를 강제 |
| `MAC_WAIT_SECONDS` | `180` | auto에서 macos 실행기를 기다리는 시간. 넘으면 home |
| `ROLLBACK_SHA` | 빈 값 | 비상 되돌리기: 채우면 빌드 없이 그 커밋의 이미지로 배포한다(production은 그대로) |

## 이전 sha로 되돌리기

production은 앞으로만 간다(강제 push 금지). 그래서 되돌리기도 「앞으로 가는 커밋」으로 한다.

**정석: main에 revert PR.** `git revert <나쁜 커밋>` → PR → pr-check 초록 → 병합. release.yml이 검사 → 이미지 → 승격을 그대로 밟고 Jenkins가 그 sha를 배포한다. 운영과 main이 어긋나지 않는다.

**급할 때: Jenkins `ROLLBACK_SHA`.** `sandcorp-auth` 「Build with Parameters」 → `ROLLBACK_SHA=<되돌릴 커밋 sha 40자>`. 굽기·검사 없이 ghcr에 그 sha 이미지가 있는지 보고(상한 5분) 지금 production의 compose·스크립트로 배포한다.
- production은 그대로라 다음 승격(main 병합)이 다시 앞으로 간다 — 곧바로 revert PR을 넣어 main을 맞춘다.
- ghcr에 그 sha 이미지가 있어야 한다(정리 잡 `ghcr-prune`이 오래된 것을 지운다).

공통: migrate는 앞으로만 간다. 되돌리는 코드가 새 스키마를 못 읽으면 DB를 따로 되돌려야 한다(파괴적 스키마 변경은 두 번에 나눠 배포하는 규칙 그대로).

## 이 저장소의 사정

- 이미지 변수는 `AUTH_IMAGE`(compose `image: ${AUTH_IMAGE:-sandcorp-auth-web:latest}`). 로컬 `make prod-local`은 변수가 없어 빌드한다.
- 비상 길 스크립트 `scripts/ci/build-image.sh`, 환경 `AUTH_IMAGE_REPO`·`AUTH_BUILDER`(`auth-images` 빌더).
- GlitchTip release(`SENTRY_RELEASE`)는 `deploy/deploy.sh`가 `SANDCORP_IMAGE_SHA`(sandcorpDeploy가 넘기는 배포 sha)로 채운다.
- 운영 `.env`·NPMplus·DB는 그대로다. 손으로 `docker compose up`을 하면 `AUTH_IMAGE`가 없어 로컬 이름의 이미지를 찾으니, 운영에서 web을 다시 띄울 때는 Jenkins를 돌리거나 `AUTH_IMAGE=ghcr.io/sandcorporation/sandcorp-auth:<sha> docker compose … up -d --no-build --no-deps --force-recreate web`로 한다.
- Jenkins 잡 `sandcorp-auth`(브랜치 `*/production`)는 노드 `built-in`·`oracle`(비상 길이면 `macos`·home도)을 쓰고, 자격은 jenkins-shared가 이름으로 부른다(`ghcr-push-token`·`github-farrar142`·`github-sandcorporation-token`·`discord-deploy-webhook`).
- oracle 호스트의 docker가 `ghcr.io`에 읽기 로그인돼 있어야 한다. GITHUB_TOKEN으로 push하려면 ghcr 패키지 `sandcorp-auth`가 이 저장소에 연결돼 있어야 한다(Actions가 처음 만든 패키지면 자동).
