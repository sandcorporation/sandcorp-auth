# Postgres → MySQL(HeatWave) 데이터 이전 절차

#30(ADR [0002](../adr/0002-mysql-heatwave.md))을 운영에 내릴 때 조율자가 따르는 절차. 옛 compose의 Postgres(`sandcorp-auth-postgres-1`, 볼륨 `sandcorp-auth_pgdata`)에 있는 데이터를 OCI MySQL HeatWave의 빈 데이터베이스로 옮긴다. 명령은 oracle 호스트의 Jenkins 워크스페이스(`/var/jenkins_home/workspace/sandcorp-auth`)에서 친다고 본다.

옮길 운영 데이터: 대표 계정(`auth.user`)·TOTP 장치·**서명 키(EdDSA, 암호화된 개인 키 BLOB)**·클라이언트(portfolio·news·oauth2-proxy 기밀 클라이언트, CIMD·DCR 공개 클라이언트)·리소스·스코프·동의·리프레시 토큰 family·리프레시 토큰·인가 코드·감사 로그·요청 제한 카운터.

## 반드시 지킬 것: 서명 키가 그대로 옮겨져야 한다

- 서명 키 행(`oauth.signingkey`의 `kid`·`public_key`·`private_key_encrypted`·`active`·`retired_at`)이 바이트 그대로 옮겨져야 **이미 발급된 액세스 토큰·ID 토큰과 사이트들이 캐시한 JWKS가 계속 유효하다.** 새 키를 만들지 않는다(`signing_keys create`·`rotate`를 이전 중에 부르지 않는다).
- 개인 키는 `.env`의 `SIGNING_KEY_ENCRYPTION_KEY`(Fernet)로 암호화돼 있다. **이 값과 `DJANGO_SECRET_KEY`를 바꾸지 않는다.** 바꾸면 키를 풀지 못해 토큰 발급이 멈춘다.
- `dumpdata`는 BinaryField를 base64로 쓰고 `loaddata`가 `longblob`에 그대로 넣는다(로컬 리허설에서 SHA-256 일치 확인, 아래 6절).

## 0. 준비

1. HeatWave 데이터베이스가 `utf8mb4` / `utf8mb4_0900_as_cs`로 만들어졌는지 본다. 다른 콜레이션(특히 `_ai_ci`)이면 스코프 이름·리소스 URL이 대소문자를 무시하게 되므로 다시 만든다.
   ```sql
   SELECT default_character_set_name, default_collation_name FROM information_schema.schemata WHERE schema_name = 'sandcorp_auth';
   ```
2. `.env`에 `DB_HOST`(사설 IP)·`DB_PORT`·`DB_NAME`·`DB_USER`·`DB_PASSWORD`를 **더한다.** `POSTGRES_*`는 되돌릴 때를 위해 이전이 끝날 때까지 남겨 둔다(새 코드는 읽지 않는다).
3. 옛 Postgres에서 미리 확인(모두 0이어야 한다. Postgres에는 부분 유일 제약이 있었으므로 1·2는 0이 정상이다):
   ```sh
   P="docker exec -i sandcorp-auth-postgres-1 sh -c 'psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -tA'"
   eval "$P" <<'SQL'
   SELECT count(*) FROM (SELECT 1 FROM oauth_signingkey WHERE active GROUP BY active HAVING count(*) > 1) x;
   SELECT count(*) FROM (SELECT 1 FROM oauth_consent WHERE revoked_at IS NULL GROUP BY user_id, client_id, resource_id HAVING count(*) > 1) x;
   SELECT count(*) FROM (SELECT 1 FROM oauth_refreshtokenfamily WHERE revoked_at IS NULL GROUP BY consent_id HAVING count(*) > 1) x;
   SELECT count(*) FROM oauth_client WHERE client_id !~ '^[\x20-\x7e]*$';   -- ascii_bin 칼럼에 못 들어가는 client_id
   SQL
   ```

## 1. 쓰기 멈추기

auth에는 스케줄러·워커가 없다. 쓰는 것은 web뿐이므로 web을 멈춘다(이 동안 로그인·토큰 발급·리프레시가 안 된다. 이미 발급된 액세스 토큰은 사이트가 캐시한 JWKS로 계속 검증된다).

```sh
docker stop sandcorp-auth-web-1
```

## 2. 옛 이미지로 덤프

옛 이미지(`sandcorp-auth-web:latest`, 아직 Postgres 코드)를 Postgres 네트워크에 붙여 돌린다.

```sh
docker run --rm --env-file .env -e DJANGO_DEBUG=0 -e POSTGRES_HOST=postgres -e POSTGRES_PORT=5432 \
  --network sandcorp-auth_default sandcorp-auth-web:latest \
  python manage.py dumpdata --natural-foreign --indent 0 \
    -e contenttypes -e auth.permission -e sessions -e admin.logentry > auth-dump.json
```

- 빼는 것: `contenttypes`·`auth.permission`(새 DB의 `migrate`가 다시 만든다), `sessions`(대표는 다시 로그인한다; 사이트들의 세션은 각 사이트 DB에 있어 영향 없음), `admin.logentry`(admin 변경 기록 — 이 서비스의 감사 기록은 `audit.auditevent`이고, 그건 옮긴다).
- 그 밖에 빼야 할 앱·모델은 없다. 캐시 테이블은 없다. 생성 칼럼(`active_marker`·`live_marker`)은 덤프에 나오지 않고 MySQL이 넣을 때 계산한다.
- 건수와 서명 키 지문을 적어 둔다(4절에서 대조):
  ```sh
  eval "$P" <<'SQL'
  SELECT 'auth_user', count(*) FROM auth_user UNION ALL SELECT 'accounts_totpdevice', count(*) FROM accounts_totpdevice
  UNION ALL SELECT 'audit_auditevent', count(*) FROM audit_auditevent UNION ALL SELECT 'core_throttlecounter', count(*) FROM core_throttlecounter
  UNION ALL SELECT 'oauth_authorizationcode', count(*) FROM oauth_authorizationcode UNION ALL SELECT 'oauth_client', count(*) FROM oauth_client
  UNION ALL SELECT 'oauth_consent', count(*) FROM oauth_consent UNION ALL SELECT 'oauth_refreshtoken', count(*) FROM oauth_refreshtoken
  UNION ALL SELECT 'oauth_refreshtokenfamily', count(*) FROM oauth_refreshtokenfamily UNION ALL SELECT 'oauth_resource', count(*) FROM oauth_resource
  UNION ALL SELECT 'oauth_scope', count(*) FROM oauth_scope UNION ALL SELECT 'oauth_signingkey', count(*) FROM oauth_signingkey;
  SELECT kid, encode(sha256(private_key_encrypted), 'hex'), active FROM oauth_signingkey ORDER BY id;
  SQL
  curl -s https://auth.sandcorp.co.kr/.well-known/jwks.json > jwks-before.json   # web을 멈추기 전에 떠 두면 더 좋다
  ```

## 3. 새 스키마에 넣기 (병합 전에)

빈 DB를 web이 먼저 보지 않도록, **PR 브랜치 이미지로 HeatWave에 `migrate` → `loaddata`를 먼저 끝내고** 병합한다. 그러면 Jenkins 배포의 `migrate`는 할 일이 없고 web은 데이터가 든 DB로 뜬다.

```sh
git fetch origin feat-30-mysql && git worktree add /tmp/auth-mysql origin/feat-30-mysql
docker build -t sandcorp-auth-web:mysql-cutover /tmp/auth-mysql
R="docker run --rm -i --env-file .env -e DJANGO_DEBUG=0 sandcorp-auth-web:mysql-cutover"
$R python manage.py check --database default      # HeatWave에 닿는지
$R python manage.py migrate --noinput             # 빈 스키마에서 oauth.0008까지
$R sh -c 'cat > /tmp/d.json && python manage.py loaddata /tmp/d.json' < auth-dump.json
```

- `migrate`가 만든 리소스·스코프(0003·0007 데이터 마이그레이션)는 `loaddata`가 같은 pk로 덮어쓴다(리허설에서 충돌 없음).
- MySQL DDL은 트랜잭션이 아니다. `migrate`가 중간에 실패하면 데이터베이스를 지우고 다시 만든 뒤 처음부터 한다(빈 DB라 잃을 것이 없다).
- `loaddata`가 넣은 명시 id 다음부터 AUTO_INCREMENT가 이어진다(InnoDB가 따라 올린다).

## 4. 대조

HeatWave에서(`mysql -h $DB_HOST -u $DB_USER -p $DB_NAME`):

```sql
SELECT 'auth_user', count(*) FROM auth_user UNION ALL SELECT 'accounts_totpdevice', count(*) FROM accounts_totpdevice
UNION ALL SELECT 'audit_auditevent', count(*) FROM audit_auditevent UNION ALL SELECT 'core_throttlecounter', count(*) FROM core_throttlecounter
UNION ALL SELECT 'oauth_authorizationcode', count(*) FROM oauth_authorizationcode UNION ALL SELECT 'oauth_client', count(*) FROM oauth_client
UNION ALL SELECT 'oauth_consent', count(*) FROM oauth_consent UNION ALL SELECT 'oauth_refreshtoken', count(*) FROM oauth_refreshtoken
UNION ALL SELECT 'oauth_refreshtokenfamily', count(*) FROM oauth_refreshtokenfamily UNION ALL SELECT 'oauth_resource', count(*) FROM oauth_resource
UNION ALL SELECT 'oauth_scope', count(*) FROM oauth_scope UNION ALL SELECT 'oauth_signingkey', count(*) FROM oauth_signingkey;
SELECT kid, sha2(private_key_encrypted, 256), active FROM oauth_signingkey ORDER BY id;   -- 2절 지문과 같아야 한다
SELECT count(*) FROM oauth_signingkey WHERE active_marker = 1;                            -- 1
```

건수·지문이 하나라도 다르면 병합하지 않는다(web을 `docker start sandcorp-auth-web-1`로 되살리면 옛 상태 그대로다).

## 5. 병합·배포·스모크

1. PR을 병합한다 → Jenkins가 새 이미지로 `deploy.sh`(DB 접속 대기 → `migrate`(변경 없음) → web 교체)를 돈다. 옛 `sandcorp-auth-postgres-1`은 compose 파일에서 빠졌으므로 고아로 남는다(되돌릴 때 쓴다).
2. 스모크:
   ```sh
   H=https://auth.sandcorp.co.kr
   curl -fsS $H/api/health                                    # {"status":"ok","db":"ok",...}
   curl -fsS $H/.well-known/jwks.json > jwks-after.json && diff <(jq -S . jwks-before.json) <(jq -S . jwks-after.json)   # 같아야 한다
   curl -fsS $H/.well-known/oauth-authorization-server >/dev/null && curl -fsS $H/.well-known/openid-configuration >/dev/null
   docker exec sandcorp-auth-web-1 python manage.py signing_keys list   # 같은 kid, 활성 1개
   docker exec sandcorp-auth-web-1 python manage.py clients list        # portfolio·news·oauth2-proxy
   ```
3. 브라우저로: `$H/login`(비밀번호+TOTP — TOTP 장치가 옮겨졌으면 등록 화면 없이 코드만 묻는다) → sandcorp.co.kr·news 관리 화면 로그인(기밀 클라이언트 코드 플로우) → oauth2-proxy로 지키는 호스트 하나. claude.ai 커넥터는 다음 리프레시에서 기존 리프레시 토큰으로 회전되는지 감사 로그(`token.refreshed`)로 본다.

## 6. 로컬 리허설 결과 (#30, 2026-10-23)

옛 코드(main `0cc5c72`, Postgres 17 `sandcorp-auth-dev`)에 시드를 넣고 → `dumpdata`(위 2절 옵션) → 새 코드로 로컬 MySQL 26.10.0(`utf8mb4_0900_as_cs`) 빈 DB에 `migrate` → `loaddata`.

- 시드: 서명 키 2개(`create` 후 `rotate` — 활성 1·은퇴 1), 대표 계정(TOTP 등록), 기밀 클라이언트 3개(portfolio·news·oauth2-proxy), DCR 공개 클라이언트 1개, 로그인 실패 1번(요청 제한 카운터·감사 로그), 인가 코드 → 토큰 교환 → 리프레시 1번 회전.
- `loaddata`: `Installed 37 object(s) from 1 fixture(s)`, 오류 없음.
- 건수: 12개 테이블 모두 일치(auth_user 1, accounts_totpdevice 1, audit_auditevent 11, core_throttlecounter 2, oauth_authorizationcode 1, oauth_client 4, oauth_consent 1, oauth_refreshtoken 2, oauth_refreshtokenfamily 1, oauth_resource 3, oauth_scope 8, oauth_signingkey 2).
- 서명 키: 두 행의 `kid`·`active`·암호화 개인 키 140바이트의 SHA-256이 덤프 원본과 일치. 이전 뒤 `published_jwks()`가 이전 전과 같고, **이전 전에 발급된 액세스 토큰이 이전 뒤 JWKS로 검증된다.**
- 리프레시: 이전 전에 받은 리프레시 토큰으로 `/token`(refresh_token) → 200, 새 액세스 토큰은 옮겨 온 활성 키로 서명. 그 새 리프레시 토큰으로 한 번 더 → 200. 살아 있는 family 1개 유지.
- AUTO_INCREMENT: 감사 로그 id가 11 → 13으로 이어짐(새 행이 옮긴 id와 부딪히지 않음).

## 7. 되돌리기

병합 뒤 문제가 나면: main에서 병합 커밋을 되돌리는 PR을 병합한다 → Jenkins가 옛 compose(Postgres 서비스 포함)로 배포한다. `.env`의 `POSTGRES_*`와 볼륨 `sandcorp-auth_pgdata`가 남아 있으면 이전 직전 상태로 돌아간다(이전 뒤 HeatWave에만 쓰인 로그인·토큰은 잃는다). 일주일쯤 문제가 없으면 `docker rm -f sandcorp-auth-postgres-1`과 `docker volume rm sandcorp-auth_pgdata`, `.env`의 `POSTGRES_*`를 지운다(그 전에 볼륨을 한 번 더 `pg_dump`해 호스트 밖에 둔다).
