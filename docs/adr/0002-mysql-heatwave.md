# 0002. DB를 Postgres에서 MySQL(OCI HeatWave Always Free)로 바꾼다

- 상태: 채택 (2026-10-23, #30)

## 배경

운영 DB는 compose 안의 Postgres 17 컨테이너(볼륨 `pgdata`)였다. oracle 호스트의 메모리·CPU를 세 서비스(auth·news·portfolio)의 DB 컨테이너가 나눠 쓰고, 백업은 손으로 뜨는 `pg_dump`뿐이었다. OCI에는 Always Free MySQL HeatWave 인스턴스(MySQL 26.10, 관리형 백업, 같은 VCN의 사설 IP)가 있다. 2026-10-23에 세 저장소를 Oracle ADB와 MySQL HeatWave에 각각 올려 시험 스위트와 동시 요청 탐침으로 검증했고, MySQL이 맞는다고 판정했다. Oracle ADB는 Django 지원 등급이 낮고 손볼 곳이 더 많았다.

## 결정

1. **MySQL 단일 백엔드.** Postgres 지원과 `psycopg`를 지운다. 환경 변수로 엔진을 고르는 분기는 두지 않는다. 드라이버는 Django 1순위인 `mysqlclient`(이미지 빌드 단계에서 MariaDB Connector/C로 빌드, 런타임에는 `libmariadb3`만).
2. 데이터베이스는 `utf8mb4` / **`utf8mb4_0900_as_cs`**(대소문자·악센트 구분)로 만든다. 시험 DB도 같은 콜레이션(`DATABASES["default"]["TEST"]`). `_ai_ci`면 `READ`가 `read`와, `/MCP`가 `/mcp`와 같아진다(스코프 이름·리소스 URL은 정확히 일치해야 한다).
3. `Client.client_id`(2048자)는 **`ascii_bin`** 칼럼이다. utf8mb4 2048자 유일 인덱스는 3072바이트 한도를 넘는다(1071). ASCII가 아닌 `client_id`는 DB에 묻기 전에 알 수 없는 클라이언트로 본다(CIMD면 감사 로그 `client.cimd_rejected`).
4. MySQL에는 부분(조건부) 유일 인덱스가 없다. 「조건이 참인 행은 하나」(활성 서명 키, 살아 있는 동의, 살아 있는 리프레시 family)는 **조건이 참이면 1, 아니면 NULL인 저장 생성 칼럼 + 일반 유일 제약**으로 둔다(NULL끼리는 겹치지 않는다).
5. 「없으면 넣고 잠근다」는 `INSERT IGNORE`가 아니라 **upsert**(`ON DUPLICATE KEY UPDATE`)로 쓴다. 무시된 중복 삽입은 공유 잠금을 잡고, 기다리던 둘이 그것을 배타 잠금으로 올리다 교착한다(1213).
6. 격리 수준은 Django MySQL 기본(READ COMMITTED)을 바꾸지 않는다. REPEATABLE READ(서버 기본)의 갭 잠금은 빈 결과에 대한 `select_for_update` 뒤 삽입끼리 교착시킨다.

## 결과

- 기존 마이그레이션 `oauth.0002`를 고쳤다(`client_id`에 `db_collation="ascii_bin"`). MySQL 스키마는 빈 상태에서 만들고 데이터는 `dumpdata`/`loaddata`로 옮기므로(마이그레이션 이력을 이어받지 않는다), 0002가 MySQL에서 실패하는 한 뒤 마이그레이션으로는 고칠 수 없다. 부분 유일 대체는 새 마이그레이션 `0008_single_live_markers`.
- 연결 하나로 차례로 도는 시험은 동시성 결함을 못 본다. `tests/test_concurrency.py`가 스레드 8개·실제 연결로 위 4·5와 인가 코드 1회 사용·리프레시 회전을 고정한다. 앞으로 「삽입 후 잠금」 코드를 더하면 여기에 같은 탐침을 더한다. Django는 1213 교착을 다시 시도하지 않는다.
- MySQL DDL은 트랜잭션이 아니다. 마이그레이션이 중간에 실패하면 앞 단계까지 적용된 채 남으므로 손으로 되돌린다(`migrate <앱> <앞 번호>`).
- 백업은 HeatWave 관리형으로 넘어간다. 로컬 시험·개발은 `make db`의 `mysql:26.10.0` 컨테이너(127.0.0.1:15444).
