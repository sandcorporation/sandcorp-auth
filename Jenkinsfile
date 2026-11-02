// main에 푸시하면: 이미지를 oracle 밖에서 굽고(mac 우선, 못 잡으면 home) ghcr에 올린 뒤, oracle은 받아서 교체만 한다(#68).
// 패턴 설명·다른 저장소로 옮기는 법: docs/ops/offhost-build.md
//
//   이미지 빌드   macos(M4, arm64 네이티브) → 3분(MAC_WAIT_SECONDS) 안에 실행기를 못 잡으면 home(built-in, QEMU).
//                 넘어가는 건 「노드를 못 잡았을 때」뿐이다 — mac에서 빌드가 실패하면 실패로 끝낸다.
//   배포(oracle)  굽지 않는다. ghcr.io/sandcorporation/sandcorp-auth:<커밋 sha>를 pull해 migrate·교체·헬스 확인.
//
// .env는 여기서 만들지 않는다. oracle 워크스페이스에 놓아 둔 것을 compose가 ./.env로 읽는다
// (oracle 호스트의 /var/jenkins_home/workspace/sandcorp-auth/.env). 시험은 로컬에서만 돌린다(CI 없음).
// Jenkins 스크립트 승인이 필요한 API(Jenkins.instance 등)를 쓰지 않는다 — 표준 단계만.

def IMAGE_REPO = 'ghcr.io/sandcorporation/sandcorp-auth'

// 이 노드에서 체크아웃하고 이미지를 굽는다. where = macos | home. 커밋 sha는 env.DEPLOY_SHA에 남긴다.
def buildImage(String where) {
  def scmVars = checkout scm
  env.DEPLOY_SHA = scmVars.GIT_COMMIT
  env.BUILT_ON = where
  currentBuild.description = "${env.DEPLOY_SHA.take(12)} · 빌드 ${where}"
  echo "== 빌드 노드: ${where} (${env.NODE_NAME})"
  withCredentials([
    string(credentialsId: 'ghcr-push-token', variable: 'GHCR_TOKEN')
  ]) {
    sh "bash scripts/ci/build-image.sh ${where}"
  }
}

pipeline {
  agent none

  options {
    disableConcurrentBuilds()
    timeout(time: 90, unit: 'MINUTES')   // home(QEMU)에서 캐시 없이 구우면 길다
    timestamps()
  }

  parameters {
    choice(name: 'BUILDER', choices: ['auto', 'macos', 'home'], description: 'auto=macos 먼저, 못 잡으면 home. 시험용으로 강제 선택')
    string(name: 'MAC_WAIT_SECONDS', defaultValue: '180', description: 'auto에서 macos 실행기를 기다리는 시간(초). 넘으면 home')
    string(name: 'ROLLBACK_SHA', defaultValue: '', description: '비우지 않으면 빌드 없이 이 커밋 sha의 이미지(ghcr)로 되돌린다 — docs/ops/offhost-build.md')
  }

  triggers {
    githubPush()
  }

  stages {
    stage('이미지 빌드') {
      when { expression { !params.ROLLBACK_SHA?.trim() } }
      steps {
        script {
          def b = params.BUILDER
          if (b == 'macos') {
            node('macos') { buildImage('macos') }
          } else if (b == 'home') {
            node('built-in') { buildImage('home') }
          } else {
            // auto: macos를 잡으면 거기서 끝까지 굽는다. 대기가 길어지면 watchdog가 실패해 failFast로 mac 대기를
            // 걷어 내고(대기열 항목이 취소된다) home으로 간다. 실행기를 잡은 뒤의 실패는 그대로 실패다.
            env.MAC_ACQUIRED = 'false'
            def waitSec = (params.MAC_WAIT_SECONDS ?: '180') as int
            try {
              parallel(
                failFast: true,
                'macos': {
                  node('macos') {
                    env.MAC_ACQUIRED = 'true'
                    buildImage('macos')
                  }
                },
                '대기 감시': {
                  def waited = 0
                  while (env.MAC_ACQUIRED != 'true' && waited < waitSec) {
                    sleep time: 5, unit: 'SECONDS'
                    waited += 5
                  }
                  if (env.MAC_ACQUIRED != 'true') {
                    error("macos 실행기를 ${waitSec}초 안에 못 잡았다")
                  }
                }
              )
            } catch (err) {
              if (env.MAC_ACQUIRED == 'true') { throw err }
              echo "macos를 못 잡아 home에서 굽는다: ${err.getMessage()}"
              node('built-in') { buildImage('home') }
            }
          }
        }
      }
    }

    stage('배포') {
      agent { label 'oracle' }
      steps {
        script {
          def sha = params.ROLLBACK_SHA?.trim() ?: env.DEPLOY_SHA
          // 배포 스크립트·compose는 이 빌드의 커밋 것을 쓴다(되돌릴 때는 지금 main 것 + 옛 이미지).
          def scmVars = checkout scm
          if (!params.ROLLBACK_SHA?.trim() && scmVars.GIT_COMMIT != sha) {
            sh "git checkout -q --detach ${sha}"
          }
          env.AUTH_IMAGE = "${IMAGE_REPO}:${sha}"
          currentBuild.description = "${sha.take(12)} · " + (params.ROLLBACK_SHA?.trim() ? '되돌리기' : "빌드 ${env.BUILT_ON}") + ' · oracle pull'
          echo "== oracle은 굽지 않는다: ${env.AUTH_IMAGE} 를 pull"
          sh 'COMPOSE_PROJECT_NAME=sandcorp-auth COMPOSE_FILE=docker-compose.prod.yml:docker-compose.oracle.yml bash deploy/deploy.sh'
        }
      }
    }
  }

  post {
    // 결과 한 줄을 디스코드로. 웹훅은 자격증명 `discord-deploy-webhook`을 이름으로만 부른다. 알림 실패는 빌드 결과를 뒤집지 않는다.
    always {
      node('built-in') {
        catchError(buildResult: null, stageResult: null, message: '디스코드 알림 실패 — 배포 결과와 무관하다') {
          withCredentials([string(credentialsId: 'discord-deploy-webhook', variable: 'DISCORD_WEBHOOK')]) {
            script {
              def result = currentBuild.currentResult
              def mark = result == 'SUCCESS' ? '✅' : (result == 'ABORTED' ? '⚪' : '❌')
              def took = currentBuild.durationString.replace(' and counting', '')
              def text = "${mark} [Auth] 배포 ${result} — #${env.BUILD_NUMBER} (${(env.DEPLOY_SHA ?: '').take(12)}) · 빌드 ${env.BUILT_ON ?: '-'} · ${took} · ${env.BUILD_URL}"
              writeFile file: 'discord-payload.json', text: groovy.json.JsonOutput.toJson([content: text])
              sh 'curl -sS -X POST -H "Content-Type: application/json" --data @discord-payload.json "$DISCORD_WEBHOOK" > /dev/null || true'
            }
          }
        }
      }
    }
    failure {
      echo '배포 실패 — 콘솔의 빌드 노드 줄과 deploy/deploy.sh 출력을 보라.'
    }
  }
}
