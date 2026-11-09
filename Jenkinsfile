@Library('sandcorp') _

// 운영 = production 브랜치 머리(#84). 이 잡은 production만 배포한다(잡 브랜치 지정자 */production).
//
//   main push → GitHub Actions release.yml: 검사(pr-check) → 이미지(image.yml, ubuntu-24.04-arm) → production fast-forward
//   production push → 여기: 굽지도 검사하지도 않는다. ghcr.io/sandcorporation/sandcorp-auth:<sha>가 있는지 짧게(5분) 보고
//                     oracle에서 pull → deploy/deploy.sh(DB 대기 → migrate → web 교체 → 헬스)
//
// 규칙은 jenkins-shared sandcorpDeploy(deployFrom) — README 「승격 브랜치에서 배포」. 파라미터:
//   BUILD_ON=jenkins  비상 길: Actions가 못 구울 때 oracle 밖(macos, MAC_WAIT_SECONDS 안에 못 잡으면 home)에서
//                     scripts/ci/build-image.sh로 굽고 배포한다(#68). 이 길로 올린 sha는 production 머리 그대로다.
//   ROLLBACK_SHA      비상 되돌리기: 빌드 없이 그 sha의 이미지로 배포(지금 production의 compose·스크립트 + 옛 이미지).
//                     production은 그대로라 다음 승격이 다시 앞으로 간다. 정석은 main에 revert PR — docs/ops/offhost-build.md
//
// .env는 여기서 만들지 않는다. oracle 워크스페이스에 놓아 둔 것을 compose가 ./.env로 읽는다
// (oracle 호스트의 /var/jenkins_home/workspace/sandcorp-auth/.env).
// GlitchTip release(SENTRY_RELEASE)는 deploy/deploy.sh가 SANDCORP_IMAGE_SHA로 채운다(#78).
sandcorpDeploy(
  name: 'Auth',
  deployFrom: 'production',
  images: [[repo: 'ghcr.io/sandcorporation/sandcorp-auth', envVar: 'AUTH_IMAGE']],
  imageWaitHint: 'https://github.com/sandcorporation/sandcorp-auth/actions/workflows/release.yml',
  // BUILD_ON=jenkins 비상 길에서만 돈다. SANDCORP_BUILT_ON = macos | home.
  buildScript: 'bash scripts/ci/build-image.sh "$SANDCORP_BUILT_ON"',
  composeProject: 'sandcorp-auth',
  composeFiles: ['docker-compose.prod.yml', 'docker-compose.oracle.yml'],
  // 저장소 배포 스크립트(AUTH_IMAGE·COMPOSE_PROJECT_NAME·COMPOSE_FILE·SANDCORP_IMAGE_SHA를 읽는다). 되돌리기 재실행은 감당하지 않는다.
  deployScript: 'deploy/deploy.sh',
  autoRollback: false,
)
