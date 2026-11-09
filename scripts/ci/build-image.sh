#!/usr/bin/env bash
# linux/arm64 배포 이미지를 굽고 ghcr 에 올린다(#68). 비상 길: Jenkins 파라미터 BUILD_ON=jenkins 일 때 sandcorpDeploy buildScript 로 macos 또는 home 에서 부른다(기본은 GitHub Actions image.yml, #84).
#
#   scripts/ci/build-image.sh <macos|home>
#
# 환경변수: GHCR_TOKEN(ghcr 쓰기 토큰, Jenkins `ghcr-push-token`),
#           AUTH_IMAGE_REPO(기본 ghcr.io/sandcorporation/sandcorp-auth), AUTH_BUILDER(buildx 빌더 이름)
# 결과: `<repo>:<커밋 sha 40자>` 한 태그. 빌드 캐시는 `<repo>-buildcache:arm64`(레지스트리) — QEMU(home)에서 특히 크다.
# bash 3.2(macos 노드)에서도 돈다. 노드의 docker 설정은 건드리지 않고 임시 DOCKER_CONFIG 에만 토큰을 적는다.
set -euo pipefail

where="${1:-}"
case "$where" in macos|home) ;; *) echo "쓰는 법: $0 <macos|home>" >&2; exit 2 ;; esac

cd "$(dirname "$0")/../.."
repo="${AUTH_IMAGE_REPO:-ghcr.io/sandcorporation/sandcorp-auth}"
builder="${AUTH_BUILDER:-auth-images}"
sha="$(git -c safe.directory="$PWD" rev-parse HEAD)"
start="$(date +%s)"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/auth-docker.XXXXXX")"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if ! docker buildx version >/dev/null 2>&1; then
  echo "이 노드의 docker CLI 에 buildx 가 없다" >&2
  exit 1
fi

if [ -n "${GHCR_TOKEN:-}" ]; then
  orig="${DOCKER_CONFIG:-$HOME/.docker}"
  mkdir -p "$orig/buildx"
  for d in cli-plugins buildx contexts; do
    if [ -e "$orig/$d" ]; then ln -s "$orig/$d" "$tmp/$d"; fi
  done
  # auths 에 직접 적는다 — `docker login` 은 키체인(macos)·pass 를 찾다 잠겨서 실패한다.
  python3 - "$orig/config.json" "$tmp/config.json" <<'PY'
import base64, json, os, sys
src, dst = sys.argv[1:3]
try:
    with open(src) as f:
        cfg = json.load(f)
except (OSError, ValueError):
    cfg = {}
for key in ("auths", "credsStore", "credHelpers"):
    cfg.pop(key, None)
tok = os.environ["GHCR_TOKEN"].strip()
cfg["auths"] = {"ghcr.io": {"auth": base64.b64encode(f"auth-ci:{tok}".encode()).decode()}}
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(cfg, f)
PY
  export DOCKER_CONFIG="$tmp"
else
  echo "GHCR_TOKEN 이 없다 — 이 노드의 docker 로그인을 그대로 쓴다"
fi

if ! docker buildx inspect "$builder" >/dev/null 2>&1; then
  echo "빌더 $builder 를 만든다(docker-container)"
  docker buildx create --name "$builder" --driver docker-container >/dev/null
fi
docker buildx inspect --bootstrap "$builder" >/dev/null

echo "빌드 노드 $where · linux/arm64 · $repo:$sha"
cache="$repo-buildcache:arm64"
docker buildx build --builder "$builder" --platform linux/arm64 --provenance=false --push \
  --tag "$repo:$sha" \
  --label "org.opencontainers.image.source=https://github.com/sandcorporation/sandcorp-auth" \
  --label "org.opencontainers.image.revision=$sha" \
  --cache-from "type=registry,ref=$cache" \
  --cache-to "type=registry,ref=$cache,mode=max" \
  .
echo "이미지 빌드·push 완료 ($where): $(( $(date +%s) - start ))초"
