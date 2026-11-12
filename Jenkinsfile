@Library('sandcorp') _

// 운영 = production 브랜치 머리(#84). 이 잡은 production만 배포한다(잡 브랜치 지정자 */production).
//
//   main push → GitHub Actions release.yml: 검사(pr-check) → 이미지(image.yml, ubuntu-24.04-arm) → production fast-forward
//   production push → 여기: 굽지도 검사하지도 않는다. ghcr.io/sandcorporation/sandcorp-auth:<sha>가 있는지 짧게(5분) 보고
//                     oracle에서 pull → deploy/deploy.sh(DB 대기 → migrate → web 교체 → 헬스)
//
// 규칙은 jenkins-shared sandcorpDeploy(deployFrom) — README 「승격 브랜치에서 배포」. 파라미터:
//   Jenkins는 빌드하지 않는다. 배포·롤백 모두 Actions가 GHCR에 게시한 sha 이미지만 사용한다.
//   ROLLBACK_SHA는 해당 sha의 기존 GHCR 이미지를 지정한다. production은 그대로다.
//   정석은 main에 revert PR — docs/ops/offhost-build.md
//
// .env는 여기서 만들지 않는다. oracle 워크스페이스에 놓아 둔 것을 compose가 ./.env로 읽는다
// (oracle 호스트의 /var/jenkins_home/workspace/sandcorp-auth/.env).
// GlitchTip release(SENTRY_RELEASE)는 deploy/deploy.sh가 SANDCORP_IMAGE_SHA로 채운다(#78).
sandcorpDeploy(
  name: 'Auth',
  deployFrom: 'production',
  images: [[repo: 'ghcr.io/sandcorporation/sandcorp-auth', envVar: 'AUTH_IMAGE']],
  imageWaitHint: 'https://github.com/sandcorporation/sandcorp-auth/actions/workflows/release.yml',
  composeProject: 'sandcorp-auth',
  composeFiles: ['docker-compose.prod.yml', 'docker-compose.oracle.yml'],
  // 저장소 배포 스크립트(AUTH_IMAGE·COMPOSE_PROJECT_NAME·COMPOSE_FILE·SANDCORP_IMAGE_SHA를 읽는다). 되돌리기 재실행은 감당하지 않는다.
  deployScript: 'deploy/deploy.sh',
  autoRollback: false,
)
