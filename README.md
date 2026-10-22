# sandcorp-auth

auth.sandcorp.co.kr — Sandcorp 사이트들(sandcorp.co.kr, news.sandcorp.co.kr)의 대표 로그인(비밀번호 + TOTP)과 OAuth 2.1 인가 서버. claude.ai 커넥터·Claude Code 같은 공개 클라이언트(CIMD·DCR)와 두 사이트의 관리 화면 로그인(기밀 클라이언트)에 JWT 액세스 토큰을 발급한다. Django + authlib, Postgres.

- 토큰 검증 규칙(사이트 쪽): [docs/resource-server-token-validation.md](docs/resource-server-token-validation.md)
- 배포·운영: [docs/operations.md](docs/operations.md)
- 용어집: [GLOSSARY.md](GLOSSARY.md)

개발 명령은 [CLAUDE.md](CLAUDE.md) 「명령」 절(`make check` 등).
