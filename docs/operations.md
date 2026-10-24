# 운영 문서

auth.sandcorp.co.kr(sandcorp-auth)를 배포하고 운영하는 사람(조율자)이 그대로 따라 하는 문서. 명령은 복사해 쓰도록 적었다. 토큰 검증 규칙과 사이트 쪽 연동은 [`resource-server-token-validation.md`](resource-server-token-validation.md), 용어는 [`../GLOSSARY.md`](../GLOSSARY.md).

## 0. 구성 한눈에

- oracle 호스트에서 Jenkins가 main 푸시마다 `deploy/deploy.sh`를 돈다(`Jenkinsfile`): 이미지 빌드 → DB 접속 대기(`manage.py check --database default`, 2초 간격 30번) → `migrate` → web 교체 → 헬스 확인.
- compose 프로젝트 이름 `sandcorp-auth`, 파일 `docker-compose.prod.yml` + `docker-compose.oracle.yml`, 서비스 `web`(gunicorn, :8000) 하나. 컨테이너 이름은 `sandcorp-auth-web-1`.
- DB는 compose 밖의 **OCI MySQL HeatWave**(MySQL 26.10, 같은 VCN의 사설 IP, 데이터베이스 `utf8mb4` / `utf8mb4_0900_as_cs`)다. web이 `.env`의 `DB_*`로 붙는다(ADR [0002](adr/0002-mysql-heatwave.md)). Postgres에서 옮길 때의 절차는 [`ops/db-migration.md`](ops/db-migration.md).
- web은 docker 브리지 게이트웨이 `172.17.0.1:18093`에만 묶인다. 바깥은 NPMplus가 TLS를 끝내고 `https://auth.sandcorp.co.kr` → `http://172.17.0.1:18093`으로 넘긴다.
- 비밀 값은 Jenkins 워크스페이스의 `.env`(oracle 호스트 `/var/jenkins_home/workspace/sandcorp-auth/.env`)에만 있다. 저장소에는 `.env.example`뿐이다.

### 관리 명령 실행하는 법

아래 문서의 `manage …`는 web 컨테이너 안의 `python manage.py …`다. oracle 호스트에서 둘 중 하나로 부른다.

```sh
# (가) 컨테이너 이름으로 — 어느 디렉터리에서나
docker exec -it sandcorp-auth-web-1 python manage.py <명령>

# (나) compose로 — Jenkins 워크스페이스에서
cd /var/jenkins_home/workspace/sandcorp-auth
docker compose -p sandcorp-auth -f docker-compose.prod.yml -f docker-compose.oracle.yml exec web python manage.py <명령>
```

비밀번호를 프롬프트로 받는 명령(`owner create`·`owner set-password`)은 `-it`(compose `exec`는 기본으로 TTY)가 있어야 한다.

## 1. env 변수

`.env.example`을 복사해 채운다. settings가 읽는 값 전부다(`grep -n 'env(' backend/config/settings.py`).

| 이름 | 필수 | 뜻 | 운영 값 / 만드는 법 |
| --- | --- | --- | --- |
| `DJANGO_SECRET_KEY` | 필수 | Django 서명 비밀(세션·CSRF). 없으면 기동 실패 | `python3 -c 'import secrets; print(secrets.token_urlsafe(50))'` |
| `DJANGO_ALLOWED_HOSTS` | 필수 | 받는 Host(쉼표 구분). **첫 값**을 헬스 체크가 Host 헤더로 쓴다 | `auth.sandcorp.co.kr` |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | 필수 | 폼 POST(로그인·동의·admin)를 받는 origin | `https://auth.sandcorp.co.kr` |
| `DJANGO_ADMIN_PATH` | 필수(사실상) | Django admin 경로. 생략하면 `admin/` | 추측하기 어려운 값. `python3 -c 'import secrets; print(secrets.token_urlsafe(12))'` |
| `SITE_URL` | 선택 | 서비스 절대 URL = 토큰 `iss`·메타데이터 `issuer`. 끝 `/` 없이 | `https://auth.sandcorp.co.kr`(기본값과 같음) |
| `SIGNING_KEY_ENCRYPTION_KEY` | 필수 | DB의 서명 개인 키를 암호화하는 Fernet 키. 없으면 기동 실패. **잃으면 서명 키를 못 푼다**(5절) | `docker run --rm sandcorp-auth-web:latest python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`(이미지가 아직 없으면 `cryptography`가 깔린 아무 Python) |
| `SESSION_AGE_SECONDS` | 선택 | 이 서비스의 로그인 세션 수명(초). 로그인 시각부터 세며 활동해도 늘지 않고 브라우저를 닫아도 유지된다 | 기본 `604800`(7일) |
| `TRUST_X_FORWARDED_FOR` | 선택 | 호출자 IP를 `X-Forwarded-For` 첫 값으로 볼지. 요청 제한·감사 로그의 IP가 여기서 나온다 | NPMplus 뒤라 `1`(기본). 직접 노출할 때만 `0` |
| `DJANGO_LOG_LEVEL` | 선택 | 루트 로그 수준 | 기본 `INFO` |
| `GUNICORN_WORKERS` | 선택 | gunicorn 워커 수 | 기본 `2`(web은 cpus 0.6, 512MB) |
| `DB_HOST` | 필수 | HeatWave 인스턴스의 사설 IP | OCI 콘솔의 DB 시스템 엔드포인트 |
| `DB_PORT` | 선택 | MySQL 포트 | 기본 `3306` |
| `DB_NAME` | 선택 | 데이터베이스 이름(`utf8mb4` / `utf8mb4_0900_as_cs`로 만든 것) | 기본 `sandcorp_auth` |
| `DB_USER` | 선택 | 그 데이터베이스에 전체 권한을 가진 서비스 계정 | 기본 `sandcorp_auth` |
| `DB_PASSWORD` | 필수 | 그 계정의 비밀번호 | HeatWave에서 계정을 만들 때 정한 값 |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | 선택 | Google 로그인(일반 사용자) OAuth 클라이언트. 하나라도 비면 Google 버튼이 없고 `/login/google*`은 404 | 보류(9절) — 지금은 비워 둔다 |
| `KAKAO_CLIENT_ID` / `KAKAO_CLIENT_SECRET` | 선택 | Kakao 로그인. `KAKAO_CLIENT_ID`는 「REST API 키」, 시크릿은 「Client Secret」 코드. 하나라도 비면 Kakao 버튼이 없다 | 9절 Kakao 절차(codemit과 같은 비즈 앱의 기존 키) |
| `HTTP_BIND` / `HTTP_PORT` | 선택 | web을 묶을 호스트 주소·포트 | oracle 덮어쓰기 기본 `172.17.0.1` / `18093` |

compose가 직접 넣으므로 `.env`에 두지 않는 것: `DJANGO_DEBUG`(운영 `0` 고정), `DJANGO_STATIC_ROOT`(이미지 기본값).

**운영 `.env`에 넣지 않는 것**: `AUTHLIB_INSECURE_TRANSPORT`. http로 OAuth 요청을 받게 하는 스위치라 **로컬 확인 때만** 쓴다(8절).

## 2. 첫 배포

1. **`.env` 준비** — oracle 호스트에서 `.env.example`을 `/var/jenkins_home/workspace/sandcorp-auth/.env`로 복사해 1절대로 채운다(Jenkins 체크아웃은 추적하지 않는 파일을 지우지 않는다). `SIGNING_KEY_ENCRYPTION_KEY`와 `.env` 전체는 바로 5절의 백업 자리에도 둔다.
2. **NPMplus 프록시 호스트** — 4절대로 만든다(Let's Encrypt).
3. **배포** — main에 푸시하면 Jenkins가 `deploy/deploy.sh`를 돈다. 마이그레이션도 여기서 된다(자원·스코프 시드 포함: `https://sandcorp.co.kr/mcp`의 `admin`·`login`, `https://news.sandcorp.co.kr/mcp`의 `admin`·`editor`·`login`). 콘솔 끝에 `{"status": "ok", "db": "ok", …}`가 나오면 된 것이다.
4. **서명 키 만들기**

   ```sh
   docker exec -it sandcorp-auth-web-1 python manage.py signing_keys create
   # → created active key <kid>
   ```

   활성 키가 이미 있으면 종료 코드 1로 거부한다(그대로 두면 된다).
5. **대표 계정 만들기** — username은 `farrar142`(토큰 `sub`이자 사이트 설정 `AUTH_OWNER_SUB`).

   ```sh
   docker exec -it sandcorp-auth-web-1 python manage.py owner create --username farrar142
   # 비밀번호: / 비밀번호 확인: (12자 이상, 흔한 비밀번호 거부)
   ```

   셸 기록에 남지 않게 `--password`는 쓰지 않는다. 계정은 하나뿐이라 두 번째 `create`는 종료 코드 1.
6. **첫 로그인과 TOTP 등록** — 브라우저로 `https://auth.sandcorp.co.kr/login` → username·비밀번호 → 화면의 QR(또는 비밀 문자열)을 인증 앱에 등록하고 6자리 코드를 넣는다. 이후 로그인은 비밀번호 + TOTP 코드다.
7. **두 사이트의 기밀 클라이언트 만들기**(사이트 관리 화면 로그인용). portfolio의 admin 경로는 portfolio `.env`의 실제 값으로 바꿔 넣는다 — **끝 슬래시 포함**, 문자 하나까지 같아야 한다.

   ```sh
   docker exec -it sandcorp-auth-web-1 python manage.py clients create-confidential --name "sandcorp.co.kr 관리" --redirect-uri "https://sandcorp.co.kr/<portfolio admin 경로>/oauth/callback/"
   docker exec -it sandcorp-auth-web-1 python manage.py clients create-confidential --name "뉴스 관리" --redirect-uri "https://news.sandcorp.co.kr/auth/callback"
   ```

   출력(시크릿은 **이때 한 번만** 보인다. DB에는 해시만 남는다):

   ```
   기밀 클라이언트를 만들었습니다.
   name: 뉴스 관리
   client_id: 5_uKwWLN72j9_e9N1U5ZAA
   client_secret: smP-7mzLaO3l…
   redirect_uris: https://news.sandcorp.co.kr/auth/callback
   시크릿은 지금 한 번만 보입니다(저장된 것은 해시뿐). 사이트 설정에 바로 넣으세요.
   ```

   `client_id`·`client_secret`을 바로 각 사이트의 운영 `.env`(그 사이트의 Jenkins 워크스페이스)에 넣고 그 사이트를 다시 배포한다. 사이트 쪽 변수 이름은 그 저장소의 `.env.example`을 따른다. 사이트가 쓰는 나머지 값:

   | 사이트 | 리다이렉트 URI | resource | scope | 토큰 인증 |
   | --- | --- | --- | --- | --- |
   | portfolio | `https://sandcorp.co.kr/<admin 경로>/oauth/callback/` | `https://sandcorp.co.kr/mcp` | `login` | `client_secret_basic` |
   | 뉴스 | `https://news.sandcorp.co.kr/auth/callback` | `https://news.sandcorp.co.kr/mcp` | `login` | `client_secret_basic` |

   그 밖에 두 사이트 공통: 발급자 `https://auth.sandcorp.co.kr`, JWKS `https://auth.sandcorp.co.kr/.well-known/jwks.json`, `AUTH_OWNER_SUB=farrar142`. admin(`/<DJANGO_ADMIN_PATH>/oauth/client/add/`)에서도 같은 것을 만들 수 있다(저장 뒤 메시지로 시크릿 한 번).
8. **확인**

   ```sh
   curl -s https://auth.sandcorp.co.kr/api/health
   # {"status": "ok", "db": "ok", "time": "…"}
   curl -s https://auth.sandcorp.co.kr/.well-known/oauth-authorization-server | python3 -m json.tool
   # "issuer": "https://auth.sandcorp.co.kr", endpoint들이 모두 https://auth.sandcorp.co.kr/…
   curl -s https://auth.sandcorp.co.kr/.well-known/jwks.json
   # {"keys": [{"kty": "OKP", "kid": "<4번의 kid>", …}]}
   curl -sI https://auth.sandcorp.co.kr/login | grep -iE 'strict-transport|x-frame|referrer'
   # Strict-Transport-Security: max-age=31536000 / X-Frame-Options: DENY / Referrer-Policy: same-origin
   docker exec sandcorp-auth-web-1 python manage.py clients list
   ```

   마지막으로 각 사이트의 관리 화면 로그인 버튼으로 한 번씩 들어가 본다(동의 화면 → 허락 → 사이트 관리 화면).

## 3. 운영 명령

| 할 일 | 명령 / 자리 | 설명 |
| --- | --- | --- |
| 서명 키 회전 | `manage signing_keys rotate` | 새 활성 키를 만들고 이전 키는 **10분 동안** JWKS에 남긴다(그동안 이전 키로 서명된 액세스 토큰(수명 10분)이 검증된다). 사이트는 모르는 `kid`를 만나면 JWKS를 다시 받는다 |
| 서명 키 목록 | `manage signing_keys list` | `kid`·상태(active/retired)·만든 시각·은퇴 시각 |
| 비밀번호 초기화 | `docker exec -it sandcorp-auth-web-1 python manage.py owner set-password` | 프롬프트로 새 비밀번호 |
| TOTP 초기화(폰 분실) | `manage owner reset-totp` | 장치를 지운다. 다음 로그인에서 다시 등록한다 |
| 클라이언트 시크릿 재발급 | `manage clients rotate-secret --client-id <id>` 또는 admin 클라이언트 변경 화면 「시크릿 재발급」 | 옛 시크릿은 **즉시** 무효. 새 시크릿을 사이트 `.env`에 넣고 사이트를 다시 배포할 때까지 그 사이트 관리 화면 로그인이 실패한다 |
| 클라이언트 목록 | `manage clients list` | `client_id  kind  registered_via  active|inactive  name  redirect_uris  members=on|off` |
| 일반 사용자 허용 켜기·끄기 | `manage clients members --client-id <id> --allow` / `--deny`, 만들 때 `create-confidential … --allow-members`, 또는 admin 클라이언트 변경 화면 「일반 사용자 허용」 | 기본 꺼짐. 켜진 클라이언트만 일반 사용자(소셜 로그인 계정)에게 코드·토큰을 준다(ADR 0003). 감사 `client.members_changed`. 대표만 받는 기존 사이트(portfolio, 뉴스, metrics, oauth2-proxy)는 켜지 않는다 |
| 클라이언트 폐기 | admin → 클라이언트(`/<admin>/oauth/client/`) → 고르고 action 「선택한 클라이언트 폐기(비활성)」 | 이후 인가·토큰 요청이 거부된다 |
| CIMD 캐시 비우기 | 같은 목록 → action 「CIMD 캐시 비우기」 | 다음 요청 때 메타데이터 문서를 다시 가져온다 |
| 리다이렉트 URI 고치기 | admin 클라이언트 변경 화면의 `redirect_uris`(JSON 목록) | 기밀은 https만, 공개는 https 또는 `localhost`·`127.0.0.1`의 http. 정확히 일치 비교라 끝 슬래시도 값이다 |
| 동의 폐기 | admin → 동의(`/<admin>/oauth/consent/`) → action 「선택한 동의 폐기(리프레시 토큰 패밀리도 폐기)」 | 다음 인가 때 동의 화면이 다시 뜬다 |
| 리프레시 토큰 패밀리 폐기 | admin → 리프레시 토큰 패밀리(`/<admin>/oauth/refreshtokenfamily/`) → action 「선택한 패밀리 폐기」 | 그 패밀리의 리프레시 토큰이 모두 무효. 이미 나간 액세스 토큰은 만료(10분)까지 산다 |
| 대표 이메일·이름(OIDC) | `manage owner set-email --email <주소>` · `manage owner set-name --name <이름>` | ID 토큰·userinfo의 `email`(+`email_verified`)·`name`. 비우면 클레임이 빠진다. oauth2-proxy는 email이 없으면 로그인을 막으므로 forward auth 전에 넣는다 |
| 자원·스코프 추가 | admin → 자원(`/<admin>/oauth/resource/`) | 스코프는 자원 변경 화면 아래 인라인 |
| 약관 새 버전 등록 | `manage terms add --kind terms|privacy --doc-version <이름> --effective YYYY-MM-DD --url <공개 주소>` 또는 admin → 약관 문서(`/<admin>/accounts/termsdocument/`) 「추가」 | 시행일이 되면 그 버전이 현재 버전이 되고, 아직 동의하지 않은 일반 사용자는 다음 로그인·`/authorize`에서 동의 화면을 본다(그 전까지 `/token`·리프레시도 `invalid_grant`). 등록한 버전은 고치거나 지울 수 없다. 감사 `terms.registered`. 10절 |
| 약관 버전 목록 | `manage terms list` | `*`가 시행 중인 현재 버전 |

`<admin>`은 `DJANGO_ADMIN_PATH` 값. admin은 이 서비스 로그인(비밀번호 + TOTP)을 거친다. `client_id`는 `-`로 시작할 수 있으므로 명령에는 `--client-id=<id>`처럼 `=`로 붙여 쓴다(띄우면 옵션으로 읽혀 「expected one argument」).

### 감사 로그

admin → 감사 사건(`/<admin>/audit/auditevent/`). 읽기 전용(추가·수정·삭제 없음). 오른쪽 필터로 `kind`·`actor`·날짜, 위 검색, 날짜 계층으로 좁힌다. 열: 시각·kind·actor·client_id·ip(상세는 행을 연다).

| kind | 뜻 |
| --- | --- |
| `login.password_failed` | 비밀번호 틀림 |
| `login.totp_failed` | TOTP 코드 틀림(로그인 또는 등록) |
| `login.locked` | IP가 차단된 상태에서 시도(또는 이번 실패로 차단됨) |
| `login.delayed` | 계정 백오프 대기 중 시도 |
| `login.succeeded` | 로그인 성공 |
| `login.totp_enrolled` | TOTP 처음 등록 |
| `logout` | 로그아웃 |
| `client.registered` | DCR(`POST /register`)로 공개 클라이언트 등록 |
| `client.cimd_rejected` | CIMD 문서를 거부(가져오기 실패·규칙 위반) |
| `client.created` | 기밀 클라이언트 생성(명령·admin) |
| `client.secret_rotated` | 기밀 클라이언트 시크릿 재발급 |
| `consent.granted` / `consent.denied` | 동의 화면에서 허락 / 거부 |
| `consent.revoked` | 동의 폐기(admin, 또는 새 동의가 대체) |
| `authorization_code.issued` | 인가 코드 발급 |
| `token.issued` | 코드 교환으로 토큰 발급 |
| `token.refreshed` | 리프레시로 토큰 재발급 |
| `token.revoked` | `/revoke` 또는 admin 패밀리 폐기 |
| `token.reuse_detected` | 이미 쓴 리프레시 토큰이 다시 옴 → 패밀리 전체 폐기 |
| `token.code_reuse_detected` | 이미 쓴 인가 코드가 다시 옴 |

### 요청 제한

| 규칙 | 한도 | 잠기면 |
| --- | --- | --- |
| 로그인 실패(IP) | 15분 안에 5회 실패 → 그 IP 15분 차단 | 15분 지나면 풀림(차단 중엔 맞는 비밀번호도 거부). 성공하면 실패 횟수가 0으로 |
| 로그인 실패(계정) | 잠그지 않고 대기: 1·2·4…최대 60초, 15분 실패 없으면 잊음 | — |
| DCR `POST /register` | IP당 1시간에 10회(모든 요청) → 1시간 차단 | 1시간 뒤 |
| `POST /token`·`/revoke` | IP당 1분에 60회(모든 요청) → 60초 차단 | 60초 뒤 |

잠김을 푸는 관리 명령은 **없다**. 기다리면 풀린다. 당장 풀어야 하면 DB의 `core_throttlecounter` 행을 지운다(키 모양 `login:ip:<ip>`, `login_account:user:<username>`, `register:ip:<ip>`, `token:ip:<ip>`):

```sh
docker exec -it sandcorp-auth-web-1 python manage.py shell -c "from core.models import ThrottleCounter as T; print(T.objects.filter(key='login:ip:203.0.113.7').delete())"
# 전부 지우기: T.objects.all().delete()
```

## 4. 프록시·네트워크 전제

NPMplus 프록시 호스트:

| 항목 | 값 |
| --- | --- |
| Domain | `auth.sandcorp.co.kr` |
| Scheme / Forward Host / Port | `http` / `172.17.0.1` / `18093` |
| SSL | Let's Encrypt, Force SSL 켬, HTTP/2 켬, HSTS는 앱이 보내므로 NPMplus 쪽은 꺼도 된다 |
| 헤더 | `Host`(원래 값), `X-Forwarded-Proto: https`, `X-Forwarded-For`(호출자 IP가 첫 값) — NPMplus 기본 설정이 넘긴다 |
| 헬스 체크 | `GET /api/health` → 200 `{"status": "ok", "db": "ok", …}`, DB가 죽으면 503 |

전제와 그 이유:

- **`X-Forwarded-Proto: https`가 와야 한다.** settings `SECURE_PROXY_SSL_HEADER`가 이 헤더로 요청을 https로 본다. 없으면 authlib가 OAuth 요청을 http라며 거부하고, HSTS 헤더가 안 붙고, Secure 쿠키를 쓰는 로그인이 깨진다.
- **`X-Forwarded-For` 첫 값이 실제 호출자 IP여야 한다**(`TRUST_X_FORWARDED_FOR=1`). 요청 제한과 감사 로그 IP가 이 값이다. web 포트는 172.17.0.1에만 묶여 있어 바깥에서 이 헤더를 꾸며 직접 들어올 수 없다.
- **`SECURE_SSL_REDIRECT`는 끈다.** TLS 종료와 http→https 리다이렉트는 NPMplus(Force SSL) 몫이다. 켜면 컨테이너 안 헬스 체크(compose healthcheck·`deploy.sh`가 `http://127.0.0.1:8000/api/health`를 부른다)가 301을 받아 배포가 실패한다.
- 앱이 보내는 보안 헤더(DEBUG 아님): `Strict-Transport-Security: max-age=31536000`(https 요청에만, 서브도메인 미포함·preload 없음 — `sandcorp.co.kr`의 다른 서브도메인에 영향을 주지 않으려고), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`. 세션·CSRF 쿠키는 `Secure`, `SameSite=Lax`(사이트에서 `/authorize`로 넘어오는 최상위 이동에 세션 쿠키가 실려야 하므로 Strict가 아니다).
- `python manage.py check --deploy`(운영 설정)는 의도한 경고 셋만 남긴다: `security.W005`(HSTS 서브도메인 미포함), `security.W008`(`SECURE_SSL_REDIRECT` 꺼짐 — NPMplus 몫), `security.W021`(HSTS preload 안 함).

### forward auth(oauth2-proxy)

sandcorp-auth는 OpenID Connect 제공자이기도 하다(discovery `/.well-known/openid-configuration`, `openid`·`profile`·`email`, ID 토큰 EdDSA, `/userinfo`; 결정은 `docs/adr/0001-oidc-layer-for-forward-auth.md`). NPMplus 호스트를 대표만 보게 하려면 oauth2-proxy를 forward auth 업스트림으로 둔다. 보호할 호스트마다 아래를 한 번씩 한다(예: `app.sandcorp.co.kr`).

1. 대표 이메일이 있어야 한다: `manage owner set-email --email <주소>`.
2. 기밀 클라이언트를 만든다. 출력의 `client_id`·`client_secret`을 바로 oauth2-proxy env에 넣는다(시크릿은 한 번만 보인다).

   ```bash
   docker exec -it sandcorp-auth-web-1 python manage.py clients create-confidential \
     --name "oauth2-proxy app.sandcorp.co.kr" \
     --redirect-uri https://app.sandcorp.co.kr/oauth2/callback
   ```

3. oracle에서 oauth2-proxy를 host network의 `127.0.0.1:3000`에 띄운다(compose 조각, 이미지 태그는 고정):

   ```yaml
   services:
     oauth2-proxy:
       image: quay.io/oauth2-proxy/oauth2-proxy:v7.12.0
       network_mode: host
       restart: unless-stopped
       environment:
         OAUTH2_PROXY_CLIENT_ID: ${OAUTH2_PROXY_CLIENT_ID}
         OAUTH2_PROXY_CLIENT_SECRET: ${OAUTH2_PROXY_CLIENT_SECRET}
         OAUTH2_PROXY_COOKIE_SECRET: ${OAUTH2_PROXY_COOKIE_SECRET}  # python -c 'import secrets;print(secrets.token_hex(16))'
       command:
         - --http-address=127.0.0.1:3000
         - --provider=oidc
         - --oidc-issuer-url=https://auth.sandcorp.co.kr
         - --scope=openid profile email
         - --code-challenge-method=S256
         - --redirect-url=https://app.sandcorp.co.kr/oauth2/callback
         - --cookie-domain=app.sandcorp.co.kr
         - --whitelist-domain=app.sandcorp.co.kr
         - --cookie-secure=true
         - --cookie-refresh=5m        # 액세스·ID 토큰 수명(10분)보다 짧게: 리프레시 토큰으로 세션을 잇는다
         - --reverse-proxy
         - --set-xauthrequest
         - --email-domain=*
         - --skip-provider-button
         - --upstream=static://202
   ```

   `--insecure-oidc-*` 플래그는 필요 없다(issuer가 https이고 ID 토큰에 `email_verified=true`가 있다).
4. NPMplus의 그 프록시 호스트에서 인증 업스트림(`AUTH_REQUEST_VOIDAUTH_UPSTREAM`)을 oauth2-proxy `http://127.0.0.1:3000`으로 고른다. oauth2-proxy 쪽 동작: `GET /oauth2/auth`가 202면 통과, 401이면 로그인(`/oauth2/start?rd=<원래 URL>`)으로 보내야 하고, `/oauth2/` 경로(콜백 포함)는 oauth2-proxy가 받아야 한다 — NPMplus가 이 둘을 해 주는지 첫 설정 때 확인한다. 통과한 요청에는 `X-Auth-Request-User`(대표 username)·`X-Auth-Request-Email`·`X-Auth-Request-Preferred-Username`이 붙는다.
5. 처음 들어가면 sandcorp-auth 로그인(비밀번호+TOTP) 뒤 동의 화면에 「로그인 정보(이름·이메일) 제공」이 뜬다. 허락하면 이후에는 묻지 않는다(동의는 admin 「동의」에서 폐기).

로컬에서 해 보려면: `make dev-backend` 대신 `SITE_URL=http://172.17.0.1:8000 DJANGO_ALLOWED_HOSTS=172.17.0.1,localhost AUTHLIB_INSECURE_TRANSPORT=1 DJANGO_DEBUG=1 uv run python manage.py runserver 0.0.0.0:8000`(컨테이너와 브라우저가 같은 issuer 주소를 보게), oauth2-proxy는 `--oidc-issuer-url=http://172.17.0.1:8000 --redirect-url=http://localhost:4180/oauth2/callback --cookie-secure=false -p 127.0.0.1:4180:4180`. 기밀 클라이언트는 https 리다이렉트만 받으므로 https로 만든 뒤 로컬 DB에서만 `redirect_uris`를 http로 고친다.

## 5. 백업

| 무엇 | 어디 | 잃으면 |
| --- | --- | --- |
| MySQL | OCI HeatWave의 `sandcorp_auth` 데이터베이스 | 계정·TOTP·클라이언트·동의·리프레시 토큰·서명 키·감사 로그가 다 사라진다 |
| `.env` | `/var/jenkins_home/workspace/sandcorp-auth/.env` | 특히 `SIGNING_KEY_ENCRYPTION_KEY` — 아래 |

DB 백업은 HeatWave 관리형 자동 백업(OCI 콘솔의 DB 시스템 → 백업)에 맡긴다. 손으로 한 벌 더 뜨려면(oracle 호스트, 결과 파일은 호스트 밖에 보관) Django 덤프를 쓴다 — 서명 키(BLOB)도 base64로 들어간다:

```sh
docker exec sandcorp-auth-web-1 python manage.py dumpdata --natural-foreign --indent 0 \
  -e contenttypes -e auth.permission -e sessions -e admin.logentry > sandcorp-auth-$(date +%F).json
# 복원: 빈 DB에 migrate → loaddata (절차는 ops/db-migration.md 3절)
```

`.env`는 비밀 보관소(비밀번호 관리자 등)에 통째로 둔다. DB 덤프와 `.env`를 같은 곳에 두지 않는다(덤프 안의 서명 키는 이 키로만 풀린다).

**`SIGNING_KEY_ENCRYPTION_KEY`를 잃었을 때**: DB의 서명 개인 키를 복호화할 수 없어 토큰 발급이 실패한다. 계정·클라이언트는 그대로이므로 새 키로 서명 키만 다시 만든다.

1. 새 Fernet 키를 만들어 `.env`의 `SIGNING_KEY_ENCRYPTION_KEY`를 바꾸고 web을 다시 띄운다(Jenkins 재실행 또는 `docker compose -p sandcorp-auth -f docker-compose.prod.yml -f docker-compose.oracle.yml up -d --no-deps --force-recreate web`).
2. `manage signing_keys rotate` — 새 활성 키가 생기고 옛 키는 은퇴한다. 옛 키로 서명된 토큰은 어차피 검증할 수 없게 된 것이니 기다릴 것은 없다.
3. 사이트는 모르는 `kid`를 만나면 JWKS를 다시 받으므로 따로 할 일은 없다. 이미 나간 액세스 토큰은 무효가 되고, 리프레시 토큰(DB 저장, 서명과 무관)은 그대로 쓸 수 있다.

## 6. 클라이언트가 붙는 흐름과 문제 볼 곳

- **claude.ai 커넥터·Claude Code(공개 클라이언트)**: 리소스 서버(`https://sandcorp.co.kr/mcp` 등)가 401과 함께 이 서비스를 가리킨다 → 클라이언트가 `/.well-known/oauth-authorization-server`를 읽는다 → CIMD(`client_id`가 https URL, 문서를 가져와 검증) 또는 DCR(`POST /register`)로 등록 → 브라우저로 `/authorize`(PKCE S256과 `resource` 필수) → 대표 로그인(비밀번호 + TOTP) → 동의 화면(처음 한 번, 같은 클라이언트·자원·스코프면 다음부터 생략) → 코드 → `POST /token`으로 액세스 토큰(JWT, 10분)·리프레시 토큰(90일, 쓸 때마다 회전).
- **사이트 관리 화면(기밀 클라이언트)**: 위와 같고 `scope=login`, 토큰 교환에 `client_secret_basic`. 자세한 것은 `resource-server-token-validation.md` 7절.

문제가 생겼을 때 감사 로그에서 볼 kind:

| 증상 | 볼 곳 |
| --- | --- |
| 로그인이 안 된다 | `login.password_failed`·`login.totp_failed`·`login.locked`·`login.delayed`(IP 차단이면 3절 「요청 제한」) |
| 커넥터 등록이 안 된다 | DCR이면 `client.registered`가 있는지(없으면 등록 요청 10회/시간 한도), CIMD면 `client.cimd_rejected`의 detail(이유) |
| 동의 뒤 사이트로 못 돌아간다 | `consent.granted`·`authorization_code.issued`가 있으면 사이트 쪽(리다이렉트 URI 일치, state) 문제 |
| 토큰 교환이 실패한다 | `token.issued`가 없다 → web 로그(`docker logs sandcorp-auth-web-1`)의 `/token` 응답 코드, 기밀 클라이언트면 시크릿(401 `invalid_client`), `token.code_reuse_detected` |
| 갑자기 다시 로그인하라 한다 | `token.reuse_detected`(리프레시 토큰이 두 번 쓰여 패밀리가 폐기됨), `consent.revoked`, `token.revoked` |
| 사이트가 토큰을 거부한다 | `signing_keys list`(활성 키), 메타데이터의 `issuer`가 `https://auth.sandcorp.co.kr`인지(`SITE_URL`), 토큰 `aud`가 사이트의 resource URL인지 |

## 7. 알려진 제약

- end-session(로그아웃 전파) 엔드포인트가 없다. 사이트 로그아웃은 사이트 세션만 끊는다. 이 서비스의 세션은 `/logout`(로그인 후 첫 화면 버튼)이나 만료(로그인 후 7일)로 끝난다. 비밀번호 변경·TOTP 재설정도 열린 세션을 끝낸다.
- 계정은 대표 한 명뿐이다(`owner create`는 두 번 되지 않는다). OIDC 클레임은 `sub`·`name`·`preferred_username`·`email`·`email_verified`뿐이고 그룹·권한 클레임은 없다.
- DCR은 IP당 10회/시간, 토큰 엔드포인트(`/token`·`/revoke`)는 IP당 60회/분, 로그인은 IP당 실패 5회/15분이면 15분 차단, 계정 실패는 최대 60초 백오프.
- 액세스 토큰은 폐기할 수 없다(JWT, 10분 만료). 폐기는 리프레시 토큰·패밀리·동의 단위다.

## 8. 운영 compose를 로컬에서 끝까지 돌려 보기

배포 전 점검용. 이 저장소 루트에서:

```sh
cp .env.example .env
# 고칠 값: DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
#          DJANGO_CSRF_TRUSTED_ORIGINS=http://127.0.0.1:18093
#          SITE_URL=http://127.0.0.1:18093
#          TRUST_X_FORWARDED_FOR=0
#          SIGNING_KEY_ENCRYPTION_KEY=<새 Fernet 키>, DJANGO_SECRET_KEY·DB_PASSWORD 아무 값(DB_HOST는 무시된다 — 로컬 MySQL로 덮인다)
#          AUTHLIB_INSECURE_TRANSPORT=1   ← 로컬 확인 때만(http로 /authorize·/token을 받게 한다). 운영 .env에는 절대 넣지 않는다
make prod-local                      # = COMPOSE_PROJECT_NAME=sandcorp-auth-local COMPOSE_FILE=docker-compose.prod.yml:docker-compose.prod-local.yml bash deploy/deploy.sh (로컬 MySQL 포함)
X="docker compose -p sandcorp-auth-local -f docker-compose.prod.yml exec web python manage.py"
$X signing_keys create
$X owner create --username farrar142 --password '<12자 이상>'
$X clients create-confidential --name 시험 --redirect-uri https://example.com/cb
curl -s http://127.0.0.1:18093/.well-known/oauth-authorization-server   # issuer = http://127.0.0.1:18093
# 브라우저로 http://127.0.0.1:18093/login (127.0.0.1은 브라우저가 안전한 출처로 보므로 Secure 쿠키가 http에서도 붙는다)
make prod-local-down                 # 볼륨까지 지운다
rm .env
```

이 절차를 처음 통과시킨 기록(DCR → 인가 → 동의 → 교환 → 리프레시 → 폐기 → admin 감사 로그)은 #12의 PR에 있다.

## 9. 소셜 로그인(Google·Kakao) 콘솔 등록

일반 사용자(ADR 0003)는 Google·Kakao로만 들어온다(#36). 콘솔 등록과 `.env` 값은 조율자가 넣고, 넣은 뒤 재배포한다. 키가 비어 있는 제공자는 버튼이 숨겨질 뿐 나머지는 그대로 돈다. 지금 운영은 Kakao만 켠다(Google 보류).

콜백(Redirect) URI는 `SITE_URL` + 아래 경로다. 운영은 이 두 개를 그대로 등록한다.

- Google: `https://auth.sandcorp.co.kr/login/google/callback`
- Kakao: `https://auth.sandcorp.co.kr/login/kakao/callback`

서비스는 두 제공자 모두 `state`(세션에 묶음, 10분·1회)와 PKCE S256을 쓰고, Google에는 `nonce`도 보낸다. Google `id_token`은 Google JWKS로 RS256 서명·`aud`(= `GOOGLE_CLIENT_ID`)·`iss`(`accounts.google.com`)·`exp`·`nonce`를 검사한다. Kakao는 액세스 토큰으로 `/v2/user/me`를 읽는다(OIDC 아님). 콜백 실패는 로그인 실패와 같은 IP 제한(`login`, 15분 5회)에 세고, 감사 로그 `login.social_failed`의 `reason`에 까닭이 남는다(`state_mismatch`·`id_token_nonce`·`id_token_aud`·`id_token_expired`·`google_token_status_400` 등). 사용자가 제공자 화면에서 취소한 것(`cancelled`)은 세지 않는다.

### Google — 보류

보류(2026-10-24 사용자 결정, Kakao 먼저). 어댑터·시험은 구현돼 있으나 `GOOGLE_CLIENT_ID`·`GOOGLE_CLIENT_SECRET`을 비워 두어 버튼·경로(`/login/google*` 404)가 꺼져 있다. 켤 때 콘솔 절차를 이 자리에 적는다(콜백 `https://auth.sandcorp.co.kr/login/google/callback`).

### Kakao (Kakao Developers) — codemit과 같은 비즈 앱을 쓴다

auth는 새 앱을 만들지 않고 codemit이 쓰는 **기존 카카오 비즈 앱**(표시 이름·아이콘 Sandcorp)을 공유한다. 카카오 회원번호(`id`)는 앱마다 다르므로, 같은 앱을 써야 나중에 codemit 회원을 auth로 옮길 때 같은 회원번호로 외부 신원을 이어 붙일 수 있다(외부 신원의 제공자 `sub` = 회원번호 10진 문자열). 기존 설정은 지우지 않고 더하기만 한다.

1. (완료, 2026-10-24) **카카오 로그인 → Redirect URI**에 `https://auth.sandcorp.co.kr/login/kakao/callback` 추가. 이 경로는 코드에 고정돼 있으니 바꾸지 않는다(`SITE_URL` + `/login/kakao/callback`).
2. (완료) **동의항목**: 닉네임·카카오계정(이메일) 「필수 동의」 확인. auth는 이 둘 말고는 읽지 않는다. 이메일이 없는 카카오 계정처럼 이메일이 오지 않아도 계정은 만들어진다(이메일 없음).
3. Web 플랫폼 사이트 도메인 등록은 **필요 없다**(지금 카카오는 Redirect URI만으로 된다).
4. 키는 **기존 비즈 앱 것을 재사용**한다: 앱 키의 **REST API 키** → `KAKAO_CLIENT_ID`, 보안의 **Client Secret** 코드 → `KAKAO_CLIENT_SECRET`. Client Secret은 **재발급하지 않는다**(재발급하면 codemit도 함께 바꿔야 한다).

### 넣은 뒤 확인

1. `.env`에 `KAKAO_CLIENT_ID`·`KAKAO_CLIENT_SECRET`을 넣고 재배포한다(Google 두 값은 비워 둔다).
2. 일반 사용자를 허용한 클라이언트(`clients members --client-id <id> --allow`)의 `/authorize`로 가면 로그인 화면에 「Kakao로 계속하기」가 보인다(Google은 보류라 없다). 허용하지 않은 클라이언트나 `/login`을 바로 열면 비밀번호 폼만 보인다.
3. 각 버튼으로 끝까지 로그인해 본 뒤 admin의 감사 로그에 `member.created`·`login.social_succeeded`가 남는지 본다. 실패하면 `login.social_failed`의 `reason`을 본다(`google_token_status_400`·`kakao_token_status_401`이면 대개 Redirect URI나 시크릿 불일치).

## 10. 약관 문서(#37)

일반 사용자는 「Sandcorp 계정 이용약관」(`terms`)과 「개인정보 수집·이용」(`privacy`) 현재 버전에 모두 동의하고 만 14세 이상을 확인해야 「활성」이 되어 코드·토큰을 받는다(대표는 대상 아님). 동의는 사용자·문서 버전·시각·14세 확인으로 `accounts.TermsAgreement`에 남고, admin 「약관 동의」에서 읽기만 한다. 감사 `terms.agreed`.

**종류마다 시행 중인 버전이 하나도 없으면 아무도 동의할 수 없어 일반 사용자 가입이 막힌다**(동의 화면이 503 「지금은 가입을 받을 수 없습니다」). 그래서 일반 사용자를 받는 클라이언트(`clients members --allow`)를 켜기 전에 첫 버전을 넣는다. 데이터 마이그레이션으로 넣지 않는 까닭: 문서 주소와 시행일은 privacy-and-terms에 본문이 게시된 뒤에야 정해지고, 운영자가 정하는 값이기 때문이다.

본문은 `sandcorporation/privacy-and-terms`(GitHub Pages, 앱별 폴더 + 문서 이름 폴더, 같은 주소를 덮어쓰고 게시일은 본문에 적는다)에 먼저 게시한다. 이 서비스는 주소만 갖는다. 주소 형식은 그 저장소 관례대로 `https://sandcorporation.github.io/privacy-and-terms/account/terms/`·`…/account/privacy/`로 한다.

```sh
docker exec -it sandcorp-auth-web-1 python manage.py terms add --kind terms \
  --doc-version 2026-11 --effective 2026-11-01 \
  --url https://sandcorporation.github.io/privacy-and-terms/account/terms/
docker exec -it sandcorp-auth-web-1 python manage.py terms add --kind privacy \
  --doc-version 2026-11 --effective 2026-11-01 \
  --url https://sandcorporation.github.io/privacy-and-terms/account/privacy/
docker exec -it sandcorp-auth-web-1 python manage.py terms list   # 두 줄 모두 * 이면 된 것
```

- 버전 이름은 자유 문자열(종류마다 유일). 게시일과 맞춰 `YYYY-MM`을 권한다.
- 약관을 바꿀 때: privacy-and-terms 본문(같은 주소)을 고치고 게시일을 바꾼 뒤, 새 버전을 시행일과 함께 등록한다. 시행일 전에는 옛 버전이 현재 버전이다. 시행일(Asia/Seoul 날짜)부터 기존 일반 사용자는 다시 동의할 때까지 새 토큰·리프레시를 받지 못한다 — 앱은 로그인으로 돌아오고, 로그인·`/authorize`가 동의 화면을 먼저 보인다.
- 같은 주소를 덮어쓰므로 옛 버전의 본문은 privacy-and-terms의 git 기록이 원본이다.

