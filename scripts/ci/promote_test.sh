#!/usr/bin/env bash
# scripts/ci/promote.sh 시험 — 로컬 bare 저장소를 origin으로. 네트워크·토큰 없음.
#   bash scripts/ci/promote_test.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
promote="$here/promote.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
export GIT_CONFIG_GLOBAL=/dev/null
git init -q --bare -b main "$tmp/origin.git"
git clone -q "$tmp/origin.git" "$tmp/work" 2>/dev/null
cd "$tmp/work"
commit() { git commit -q --allow-empty -m "$1"; git rev-parse HEAD; }
A=$(commit a); B=$(commit b); C=$(commit c)
git push -q origin HEAD:main
git checkout -q --detach "$A"
X=$(commit x)  # main 밖 커밋
git checkout -q main

pass=0 fail=0
head_of() { git ls-remote --heads origin "refs/heads/production" | awk '{print $1}'; }
check() {  # 이름, 기대 종료코드, 기대 production 머리, 출력에 있어야 할 말, 명령...
  local name="$1" want_rc="$2" want_head="$3" want_out="$4"; shift 4
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" = "$want_rc" ] && [ "$(head_of)" = "$want_head" ] && grep -qF -- "$want_out" <<<"$out"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "실패: $name (rc=$rc 기대 $want_rc, 머리=$(head_of) 기대 $want_head)"; printf '  | %s\n' "$out"
  fi
}

check '없으면 만든다' 0 "$A" '만든다' bash "$promote" ff "$A"
check '같은 sha 는 할 일 없음' 0 "$A" '할 일 없음' bash "$promote" ff "$A"
check 'fast-forward' 0 "$C" 'fast-forward' bash "$promote" ff "$C"
check '늦게 끝난 옛 실행은 건너뜀' 0 "$C" '건너뜀' bash "$promote" ff "$B"
check '갈라진 sha 는 실패' 1 "$C" '갈라졌다' bash "$promote" ff "$X"
check 'sha 모양 검사' 2 "$C" '40자' bash "$promote" ff "${C:0:12}"
check '모르는 모드(rollback 없음)' 2 "$C" '쓰는 법' bash "$promote" rollback "$A"
echo "promote.sh 시험: 통과 $pass, 실패 $fail"
[ "$fail" = 0 ]
