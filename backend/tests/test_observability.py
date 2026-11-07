"""GlitchTip 연동(#78): SDK 설정, before_send의 자격 지우기·잡음 버리기, `glitchtip_test` 명령.

SDK는 실제 설정(`sentry_init_options`)으로 켜고 전송만 가짜(`_Capture`)로 바꾼다 — 네트워크를
치지 않고, 실제로 보낼 이벤트를 그대로 본다.
"""

from collections.abc import Callable, Iterator

import pytest
import sentry_sdk
from django.core.exceptions import PermissionDenied
from django.core.handlers.wsgi import WSGIHandler
from django.core.management import call_command
from django.core.management.base import CommandError
from django.core.signals import request_finished, request_started
from django.db import close_old_connections
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from django.urls import path
from sentry_sdk.envelope import Envelope
from sentry_sdk.transport import Transport

from core.observability import (
    FILTERED,
    configure_sentry,
    sentry_init_options,
)
from tests.conftest import FrozenClock

pytestmark = pytest.mark.django_db

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYXJyYXIxNDIifQ.c2lnbmF0dXJl"
SECRET = "Zx81kQp0aLm2Vn7RtY5uWc3sDf9gHj4k"
EMAIL = "member@example.com"
RELEASE = "0123456789abcdef0123456789abcdef01234567"


class _Capture(Transport):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[dict[str, object]] = []

    def capture_envelope(self, envelope: Envelope) -> None:
        event = envelope.get_event()
        if event is not None:
            self.events.append(dict(event))


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, object]]]:
    monkeypatch.setenv("SENTRY_RELEASE", RELEASE)
    transport = _Capture()
    options = sentry_init_options("https://public@glitchtip.invalid/1")
    sentry_sdk.init(**options, transport=transport)  # type: ignore[arg-type]  # TypedDict → 키워드 인자
    yield transport.events
    sentry_sdk.init()  # DSN 없이 다시 init = 끈다


def boom(request: HttpRequest) -> HttpResponse:
    raise RuntimeError(f"broke for {EMAIL} with {JWT} and {SECRET}")


def denied(request: HttpRequest) -> HttpResponse:
    raise PermissionDenied("no")


urlpatterns = [path("boom", boom), path("denied", denied)]


def wsgi_get(url: str, headers: dict[str, str] | None = None) -> str:
    """운영(gunicorn)과 같은 길 — Django의 WSGI 진입점으로 요청한다. 시험 클라이언트는 이 진입점을
    거치지 않아 SDK가 URL·헤더를 싣지 않는다. 응답 상태 줄을 돌려준다."""

    environ = RequestFactory().get(url, headers=headers).environ
    status: list[str] = []

    def start_response(
        line: str, headers: list[tuple[str, str]], exc_info: object = None
    ) -> Callable[[bytes], object]:
        status.append(line)
        return lambda body: None

    # 시험 클라이언트처럼 요청 앞뒤의 연결 닫기를 뗀다 — 시험 트랜잭션 안의 연결이다.
    request_started.disconnect(close_old_connections)
    request_finished.disconnect(close_old_connections)
    try:
        WSGIHandler()(environ, start_response)
    finally:
        request_started.connect(close_old_connections)
        request_finished.connect(close_old_connections)
    return status[0]


def test_sdk_is_off_without_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    assert configure_sentry() is False
    assert not sentry_sdk.get_client().is_active()


def test_options_are_production_without_pii(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRY_RELEASE", RELEASE)
    options = sentry_init_options("https://public@glitchtip.invalid/1")
    assert options["release"] == RELEASE
    assert options["environment"] == "production"
    assert options["send_default_pii"] is False
    assert options["include_local_variables"] is False
    assert options["max_request_body_size"] == "never"
    assert options["traces_sample_rate"] == 0.0


@pytest.mark.urls("tests.test_observability")
def test_server_error_is_sent_without_credentials(sent: list[dict[str, object]]) -> None:
    status = wsgi_get(
        "/boom?code=authcode123&state=st4te&scope=openid&next=/authorize%3Fcode%3Dx",
        headers={
            "Authorization": f"Bearer {JWT}",
            "X-Forwarded-For": "203.0.113.9",
            "Cookie": "sessionid=session-value-123; csrftoken=csrf-value-456",
        },
    )
    assert status.startswith("500")

    [event] = sent
    assert event["release"] == RELEASE
    assert event["environment"] == "production"
    text = repr(event)
    for secret in (
        JWT,
        SECRET,
        EMAIL,
        "session-value-123",
        "authcode123",
        "st4te",
        "203.0.113.9",
        "csrf-value-456",
    ):
        assert secret not in text, secret
    request = event["request"]
    assert isinstance(request, dict)
    assert "cookies" not in request and "data" not in request
    headers = {k.lower() for k in request.get("headers", {})}
    assert "authorization" not in headers and "cookie" not in headers
    assert "scope=openid" in request["query_string"]
    exception = event["exception"]
    assert isinstance(exception, dict)
    [value] = exception["values"]
    assert value["type"] == "RuntimeError"
    assert FILTERED in value["value"]
    assert all("vars" not in frame for frame in value["stacktrace"]["frames"])


@pytest.mark.urls("tests.test_observability")
def test_expected_rejections_are_dropped(sent: list[dict[str, object]]) -> None:
    assert wsgi_get("/denied").startswith("403")
    assert wsgi_get("/no-such-page").startswith("404")
    assert wsgi_get("/boom", headers={"Host": "evil.example"}).startswith("400")
    assert sent == []


def test_glitchtip_test_command_sends_onboarding_error(
    sent: list[dict[str, object]], frozen_clock: FrozenClock
) -> None:
    call_command("glitchtip_test")
    [event] = sent
    exception = event["exception"]
    assert isinstance(exception, dict)
    [value] = exception["values"]
    assert value["type"] == "GlitchTipOnboardingTest"
    assert value["value"].startswith("연동 시험 auth ")
    assert event["release"] == RELEASE
    assert event["environment"] == "production"


def test_glitchtip_test_command_fails_without_dsn() -> None:
    with pytest.raises(CommandError) as excinfo:
        call_command("glitchtip_test")
    assert excinfo.value.returncode == 1
