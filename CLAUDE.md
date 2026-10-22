# sandcorp-auth

Sandcorp 사이트들(sandcorp.co.kr, news.sandcorp.co.kr)의 대표 로그인과 OAuth 2.1 인가를 맡는 독립 인증 서비스. auth.sandcorp.co.kr.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues (`sandcorporation/sandcorp-auth`, via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage labels are used as-is: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## 작업 흐름

- 스펙은 #1, 티켓은 그 하위 이슈다. 이슈마다 워크트리 `~/workspace/sandcorp-auth-wt/<브랜치>`에서 작업하고 `origin/main`으로 PR을 연다.
- PR CI는 없다. 시험·린트·타입 검사는 로컬에서 돌린다. 통과하면 작업자가 바로 squash 병합한다(main 직접 push 금지).
- 배포와 서버 설정(env 파일, NPMplus, DNS, OCI)은 조율자가 다룬다. 작업자는 원격 호스트에 쓰지 않는다.
- 스택과 명령은 `~/workspace/portfolio`와 같은 형태를 따른다: `backend/`(uv, Python 3.13, Django, django-ninja), `make test` / `make lint` / `make typecheck` / `make check`.
