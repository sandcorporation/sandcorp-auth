# adapters

시계·난수처럼 서비스가 직접 부르면 시험이 어려워지는 외부 의존을 이 아래에 둔다.

- 서비스는 `datetime.now()`·`secrets` 를 직접 부르지 않고 `get_clock()`·`get_randomness()` 로 받는다.
- 각 어댑터는 작은 `Protocol`(쓰는 메서드만)과 실제 구현, 모듈 전역 getter/setter 를 가진다.
- 시험은 `tests/conftest.py` 의 픽스처(`frozen_clock` 등)로 가짜를 끼우고 끝나면 복원한다.

- `http.py`: 다른 호스트의 문서를 가져오는 자리(CIMD). 호스트 이름 풀이도 여기 있다. 시험은 `fake_http` 픽스처.
- `social_http.py`: 소셜 로그인 제공자(Google·Kakao)의 토큰·JWKS·사용자 API 호출. 시험은 autouse `fake_providers` 픽스처(실제 제공자를 부르지 않는다).
