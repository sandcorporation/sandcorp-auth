"""오류를 자체 GlitchTip(`glitchtip.honeycombpizza.link`, 프로젝트 `auth-backend`)으로 보낸다(#78).

받는 쪽은 sentry.io가 아니라 우리 GlitchTip이고 SDK는 `sentry-sdk`다. 선례는 codemit의
`backend/core/observability.py`다.

**DSN이 없으면 아무것도 하지 않는다.** dev·시험은 `SENTRY_DSN`을 주지 않는다(시험 설정은
일부러 비운다). 운영은 compose가 `.env`의 `SENTRY_DSN_BACKEND`를 `SENTRY_DSN`으로, Jenkins가
배포 이미지의 커밋 sha(40자)를 `SENTRY_RELEASE`로 넘긴다(`docs/operations.md` 12절).

**이 서버는 인증 서버다.** 이벤트에 실릴 수 있는 것 대부분이 자격이다 — 비밀번호·TOTP,
세션·CSRF 쿠키, `Authorization`(Bearer 토큰, 기밀 클라이언트의 Basic 시크릿), `/token` 본문의
`code`·`code_verifier`·`refresh_token`·`client_secret`, `/authorize`·소셜 콜백 쿼리의
`code`·`state`·`nonce`, 회원 이메일. 그래서 SDK 설정 하나를 믿지 않고 겹으로 막는다.

- SDK 설정: `send_default_pii=False`, 요청 본문 안 보냄(`max_request_body_size="never"`),
  프레임 지역 변수 안 보냄(`include_local_variables=False`), 성능 추적 0.
- `scrub_event`(보내기 직전): 요청의 쿠키·본문·자격 헤더·IP를 지우고, 쿼리 문자열은
  `_SAFE_QUERY_KEYS`의 값만 남긴다(모르는 키는 값을 가린다). 프레임 `vars`를 지우고,
  사용자는 `id`만 남긴다. 예외 메시지·로그 메시지·breadcrumb·extra는 키 이름이 자격이면 값을
  가리고, 문자열 속 JWT·`Bearer …`·이메일·긴 토큰 모양을 가린다.
- `drop_expected_error`: 의도한 거절은 오류가 아니다 — 404·403·`SuspiciousOperation`
  (`DisallowedHost` 등), 4xx 상태를 지닌 예외, `django.security.*` 로그, 손으로 친
  `manage.py shell`의 예외는 버린다. 5xx와 처리되지 않은 예외만 보낸다.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Final, TypedDict, cast
from urllib.parse import parse_qsl, urlencode

if TYPE_CHECKING:
    from sentry_sdk._types import Event, Hint


#: 연동 확인 명령(`manage.py glitchtip_test`)이 던지는 예외. 자동화 precheck(`pick.py`)는 이
#: 이름의 오류를 시험으로 보고 `[시험]`으로 보고한다.
class GlitchTipOnboardingTest(Exception):
    pass


ENVIRONMENT: Final = "production"
_DSN_ENV: Final = "SENTRY_DSN"
_RELEASE_ENV: Final = "SENTRY_RELEASE"
FILTERED: Final = "[Filtered]"

#: 이벤트 어디에 있든 이 이름(소문자)의 키는 값을 가린다.
_SECRET_KEYS: Final = frozenset(
    {
        "code",
        "state",
        "nonce",
        "otp",
        "totp",
        "email",
        "login_hint",
        "id_token_hint",
        "code_challenge",
        "remote_addr",
        "ip",
        "ip_address",
        "x-forwarded-for",
        "x_forwarded_for",
        "x-real-ip",
    }
)
#: 이 조각이 들어간 키(소문자)도 값을 가린다.
_SECRET_KEY_PARTS: Final = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "session",
    "csrf",
    "verifier",
    "assertion",
    "api_key",
    "apikey",
    "private_key",
    "credential",
)
#: 요청 헤더 중 통째로 지우는 것(소문자).
_DROP_HEADERS: Final = frozenset(
    {
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-csrftoken",
        "x-forwarded-for",
        "x-real-ip",
    }
)
#: 쿼리 문자열에서 값을 남기는 키. 나머지(`code`·`state`·`next`… 모르는 것 전부)는 값을 가린다.
_SAFE_QUERY_KEYS: Final = frozenset(
    {"response_type", "response_mode", "client_id", "scope", "resource", "grant_type", "prompt"}
)

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
#: 시크릿·토큰·코드 모양 — 글자와 숫자가 섞인 24자 이상 덩어리(ULID 26자 `sub`도 가려진다).
_LONG_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{24,}"
)


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _SECRET_KEYS or any(part in lowered for part in _SECRET_KEY_PARTS)


def scrub_text(text: str) -> str:
    """문자열 속 자격 모양(JWT·Bearer/Basic·이메일·긴 토큰)을 가린다."""

    text = _JWT.sub(FILTERED, text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {FILTERED}", text)
    text = _EMAIL.sub(FILTERED, text)
    return _LONG_TOKEN.sub(FILTERED, text)


def _scrub_value(value: object) -> object:
    """dict·list를 따라 내려가며 자격 키의 값과 문자열 속 자격 모양을 가린다(제자리)."""

    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        for key in list(value):
            value[key] = FILTERED if _is_secret_key(str(key)) else _scrub_value(value[key])
        return value
    if isinstance(value, list):
        for index, item in enumerate(value):
            value[index] = _scrub_value(item)
        return value
    if isinstance(value, tuple):
        return [_scrub_value(item) for item in value]
    return value


def _scrub_query(query: object) -> object:
    if not isinstance(query, str) or not query:
        return query
    pairs = parse_qsl(query, keep_blank_values=True)
    return urlencode([(k, v if k in _SAFE_QUERY_KEYS else FILTERED) for k, v in pairs])


def _scrub_request(request: dict[str, object]) -> None:
    for key in ("cookies", "data", "env"):
        request.pop(key, None)
    if "query_string" in request:
        request["query_string"] = _scrub_query(request["query_string"])
    url = request.get("url")
    if isinstance(url, str) and "?" in url:
        base, _, query = url.partition("?")
        request["url"] = f"{base}?{_scrub_query(query)}"
    headers = request.get("headers")
    if isinstance(headers, dict):
        for name in list(headers):
            if str(name).lower() in _DROP_HEADERS:
                del headers[name]


def _drop_frame_vars(container: object) -> None:
    values = container.get("values") if isinstance(container, dict) else None
    for value in values if isinstance(values, list) else ():
        stacktrace = value.get("stacktrace") if isinstance(value, dict) else None
        frames = stacktrace.get("frames") if isinstance(stacktrace, dict) else None
        for frame in frames if isinstance(frames, list) else ():
            if isinstance(frame, dict):
                frame.pop("vars", None)


def scrub_event(event: Event) -> Event:
    """보내기 직전에 자격·개인정보가 실릴 수 있는 자리를 지운다(제자리, 같은 객체를 돌려준다)."""

    data = cast(dict[str, object], event)
    request = data.get("request")
    if isinstance(request, dict):
        _scrub_request(request)
    for name in ("exception", "threads"):
        _drop_frame_vars(data.get(name))
    exception = data.get("exception")
    values = exception.get("values") if isinstance(exception, dict) else None
    for value in values if isinstance(values, list) else ():
        if isinstance(value, dict) and isinstance(value.get("value"), str):
            value["value"] = scrub_text(value["value"])
    user = data.get("user")
    if isinstance(user, dict):
        data["user"] = {"id": user["id"]} if "id" in user else {}
    for name in ("logentry", "message", "breadcrumbs", "extra", "tags"):
        if name in data:
            data[name] = _scrub_value(data[name])
    return event


_SHELL_COMMAND_MODULE: Final = "django.core.management.commands.shell"
_SHELL_COMMAND_PATH: Final = "django/core/management/commands/shell.py"


def _is_manage_shell_error(event: Event) -> bool:
    """예외 스택에 `manage.py shell` 명령 프레임이 있으면 True — 손으로 친 명령의 실수다."""

    exception = cast(dict[str, object], event).get("exception")
    values = exception.get("values") if isinstance(exception, dict) else None
    for value in values if isinstance(values, list) else ():
        stacktrace = value.get("stacktrace") if isinstance(value, dict) else None
        frames = stacktrace.get("frames") if isinstance(stacktrace, dict) else None
        for frame in frames if isinstance(frames, list) else ():
            if not isinstance(frame, dict):
                continue
            if frame.get("module") == _SHELL_COMMAND_MODULE:
                return True
            for key in ("abs_path", "filename"):
                path = str(frame.get(key) or "").replace("\\", "/")
                if path.endswith(_SHELL_COMMAND_PATH):
                    return True
    return False


def _status_code_of(exc: BaseException) -> int | None:
    status = getattr(exc, "status_code", None)
    return status if isinstance(status, int) else None


def drop_expected_error(event: Event, hint: Hint) -> Event | None:
    """의도한 거절·잡음이면 None(버림), 아니면 그대로."""

    record = hint.get("log_record")
    if record is not None and str(getattr(record, "name", "")).startswith("django.security."):
        return None
    if _is_manage_shell_error(event):
        return None
    exc_info = hint.get("exc_info")
    if not exc_info:
        return event
    exc = exc_info[1]

    from django.core.exceptions import PermissionDenied, SuspiciousOperation
    from django.http import Http404

    if isinstance(exc, (Http404, PermissionDenied, SuspiciousOperation)):
        return None
    status = _status_code_of(exc)
    if status is not None and 400 <= status < 500:
        return None
    return event


def before_send(event: Event, hint: Hint) -> Event | None:
    """SDK의 `before_send` — 의도한 거절은 버리고, 남은 것은 자격을 지워 보낸다."""

    kept = drop_expected_error(event, hint)
    return None if kept is None else scrub_event(kept)


class SentryOptions(TypedDict):
    dsn: str
    release: str | None
    environment: str
    integrations: list[object]
    send_default_pii: bool
    include_local_variables: bool
    max_request_body_size: str
    traces_sample_rate: float
    before_send: Callable[[Event, Hint], Event | None]


def sentry_init_options(dsn: str) -> SentryOptions:
    """`sentry_sdk.init`에 넘기는 설정 — 시험이 같은 설정에 가짜 전송만 바꿔 켠다."""

    from sentry_sdk.integrations.django import DjangoIntegration

    return {
        "dsn": dsn,
        "release": os.environ.get(_RELEASE_ENV, "").strip() or None,
        "environment": ENVIRONMENT,
        "integrations": [DjangoIntegration()],
        "send_default_pii": False,
        "include_local_variables": False,
        "max_request_body_size": "never",
        "traces_sample_rate": 0.0,
        "before_send": before_send,
    }


def sentry_dsn() -> str:
    return os.environ.get(_DSN_ENV, "").strip()


def configure_sentry() -> bool:
    """DSN이 있으면 SDK를 켠다(켰으면 True). `settings.py` 끝이 import 때 한 번 부른다 —
    gunicorn과 관리 명령이 모두 이 한 줄로 켜진다."""

    dsn = sentry_dsn()
    if not dsn:
        return False

    import sentry_sdk

    sentry_sdk.init(**sentry_init_options(dsn))  # type: ignore[arg-type]  # TypedDict → init의 키워드 인자
    return True
