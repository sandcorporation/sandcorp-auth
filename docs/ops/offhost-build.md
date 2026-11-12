# 이미지 빌드와 배포

운영 oracle(aarch64, 4코어)은 서비스를 위해 여유를 둔다. 운영 이미지는 GitHub Actions에서 빌드·게시하고 oracle은 GHCR에서 받아 실행만 한다.

## 빌드와 배포 흐름

```
PR ─▶ pr-check(Actions) ─▶ main 병합
main push ─▶ Actions release.yml
               check ∥ image(image.yml, ubuntu-24.04-arm) ─▶ ghcr.io/sandcorporation/sandcorp-auth:<sha>
               promote(check·image 통과 후 production fast-forward)
production push ─▶ Jenkins sandcorp-auth ─▶ GHCR 이미지 확인·pull ─▶ oracle 배포
```

- `production` 브랜치 머리는 운영 버전이다. `release.yml`은 검사와 이미지 게시가 모두 성공해야만 이를 승격한다.
- Jenkins shared-library 계약은 `sandcorpDeploy(deployFrom: 'production')`이며 이 저장소는 `buildScript`를 전달하지 않는다. 따라서 Jenkins는 빌드 노드 선택이나 이미지 빌드 없이 이미 게시된 이미지만 배포한다.
- Jenkins의 일반 배포와 `ROLLBACK_SHA` 모두 `ghcr.io/sandcorporation/sandcorp-auth:<sha>`를 사용한다. 롤백 sha에 해당하는 GHCR 이미지가 있어야 하며, Jenkins가 이미지를 빌드하거나 다른 Jenkins 노드로 넘어가는 경로는 없다.
- 이미지는 `linux/arm64`, 커밋의 40자리 sha 태그, source·revision 레이블로 게시된다. 캐시는 같은 패키지의 `:buildcache` 태그다.
- production은 fast-forward 전용이다. GitHub Actions release 실행이 검사·이미지 생성을 모두 마친 뒤 승격한다.

## 되돌리기

정석은 main에 revert PR을 만든다. PR 검사가 통과하고 병합되면 Actions가 revert 커밋 이미지를 만들고 production을 승격하며 Jenkins가 이를 배포한다.

급할 때 Jenkins `ROLLBACK_SHA`에는 **GHCR에 이미 게시된 이미지의 sha**를 지정할 수 있다. 이는 production 브랜치를 바꾸지 않는다. 이후 main에 revert PR을 올려 운영과 저장소를 일치시킨다. DB migration은 앞으로만 진행하므로, 새 스키마를 읽지 못하는 이전 이미지로 되돌릴 때는 DB를 별도로 처리해야 한다.

## 운영 환경

- compose 프로젝트 `sandcorp-auth`, 파일 `docker-compose.prod.yml` + `docker-compose.oracle.yml`, 서비스 `web`.
- Jenkins는 oracle에서 DB 접속 대기 → migrate → web 교체 → 헬스 확인을 수행한다. 운영 `.env`는 oracle의 Jenkins 워크스페이스(`/var/jenkins_home/workspace/sandcorp-auth/.env`)에 둔다.
- 컨테이너의 `AUTH_IMAGE`는 GHCR의 sha 태그다. GlitchTip release(`SENTRY_RELEASE`)는 배포 sha를 사용한다.
- Oracle Docker 데몬은 `ghcr.io`에서 pull할 권한이 있어야 한다.
