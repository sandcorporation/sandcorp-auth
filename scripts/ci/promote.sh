#!/usr/bin/env bash
# production 브랜치 옮기기(#32). GitHub Actions가 부른다 — 사람이 직접 push하지 않는다.
#
#   scripts/ci/promote.sh ff <sha>   release.yml: main 검사·이미지가 통과한 sha로 fast-forward만(강제 없음).
#                                    production이 이미 그 sha보다 새 판이면(늦게 끝난 옛 실행) 건너뛴다 — 실패가 아니다.
# production은 앞으로만 간다(ruleset이 강제 push·삭제를 막는다). 되돌리기는 main에 revert PR — docs/ops/offhost-build.md
#
# 환경변수: PROMOTE_BRANCH(기본 production), MAIN_BRANCH(기본 main), PROMOTE_REMOTE(기본 origin).
# push 자격은 actions/checkout이 남긴 GITHUB_TOKEN(승격 잡만 contents: write)이다. 이 스크립트는 토큰을 읽지 않는다.
# 시험: scripts/ci/promote_test.sh
set -euo pipefail

mode="${1:-}"
sha="${2:-}"
branch="${PROMOTE_BRANCH:-production}"
main="${MAIN_BRANCH:-main}"
remote="${PROMOTE_REMOTE:-origin}"

usage() { echo "쓰는 법: $0 ff <커밋 sha 40자>" >&2; exit 2; }
case "$mode" in ff) ;; *) usage ;; esac
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "sha는 소문자 16진수 40자여야 한다: '$sha'" >&2; exit 2; }

# 지금 production 머리(없으면 빈 값). 원격에서 직접 읽는다 — 체크아웃이 언제 받았든 상관없다.
remote_head() {
  git ls-remote --heads "$remote" "refs/heads/$1" | awk '{print $1}'
}

# 비교하려면 두 커밋이 다 있어야 한다.
fetch_commits() {
  git fetch -q --no-tags "$remote" "+refs/heads/$main:refs/remotes/$remote/$main"
  if [ -n "$(remote_head "$branch")" ]; then
    git fetch -q --no-tags "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch"
  fi
}

promote_ff() {
  fetch_commits
  local cur
  cur="$(remote_head "$branch")"
  if [ -z "$cur" ]; then
    echo "== $branch 가 없다 — $sha 로 만든다"
    git push -q "$remote" "$sha:refs/heads/$branch"
    return
  fi
  if [ "$cur" = "$sha" ]; then
    echo "== $branch 는 이미 $sha — 할 일 없음"
    return
  fi
  if git merge-base --is-ancestor "$cur" "$sha"; then
    echo "== $branch: $cur → $sha (fast-forward)"
    # 강제가 아니라서 그사이 누가 옮겼으면 서버가 거절한다 — 그때 다시 본다.
    if git push -q "$remote" "$sha:refs/heads/$branch"; then
      return
    fi
    local now
    now="$(remote_head "$branch")"
    git fetch -q --no-tags "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch"
    if git merge-base --is-ancestor "$sha" "$now"; then
      echo "== 건너뜀: push 사이에 $branch 가 이미 더 새 판($now)으로 승격됐다"
      return
    fi
    echo "$branch push 거절 — 지금 머리 $now 는 $sha 를 품지 않는다" >&2
    exit 1
  fi
  if git merge-base --is-ancestor "$sha" "$cur"; then
    echo "== 건너뜀: $branch 는 이미 더 새 판($cur)으로 승격됐다(이 실행이 늦게 끝났다)"
    return
  fi
  echo "$branch($cur)와 $sha 가 갈라졌다 — fast-forward 할 수 없다. production에 main 밖 커밋이 있는지 보라" >&2
  exit 1
}

"promote_$mode"
