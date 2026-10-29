"""Signing keys, a fake JWKS and a frozen clock for the authkit tests. No network."""

import os
import resource
import time
from collections.abc import Generator
from datetime import UTC, datetime

import pytest

from sandcorp_authkit.testing import FakeJwks, SigningKey
from sandcorp_authkit.testing import FixedClock as FrozenClock
from sandcorp_authkit.tokens import JwksCache

__all__ = ["FakeJwks", "FrozenClock", "SigningKey"]

ISSUER = "https://auth.sandcorp.co.kr"
RESOURCE = "https://sandcorp.co.kr/mcp"
OWNER = "farrar142"
MEMBER = "m_01JB2Z3Y4X5W6V7T8S9R0Q1P2N"
START = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def pytest_configure(config: pytest.Config) -> None:
    """Minimal Django for tests/test_django.py. The other modules never import Django
    (tests/test_extras.py proves it in a clean interpreter)."""
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            SECRET_KEY="authkit-tests",
            ALLOWED_HOSTS=["testserver"],
            ROOT_URLCONF=__name__,
            USE_TZ=True,
        )
        django.setup()


urlpatterns: list[object] = []


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(START)


@pytest.fixture
def key() -> SigningKey:
    return SigningKey(kid="k1")


@pytest.fixture
def fake_jwks(key: SigningKey) -> FakeJwks:
    return FakeJwks(key)


@pytest.fixture
def jwks(fake_jwks: FakeJwks, clock: FrozenClock) -> JwksCache:
    return JwksCache(fake_jwks, clock)


def claims_at(clock: FrozenClock, **overrides: object) -> dict[str, object]:
    """Claims as sandcorp-auth issues them (backend/services/tokens.py), now on `clock`.
    An override of `...` (Ellipsis) drops that claim."""
    iat = int(clock.now().timestamp())
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": OWNER,
        "aud": RESOURCE,
        "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
        "scope": "admin login",
        "iat": iat,
        "exp": iat + 600,
        "jti": "jti-1",
    }
    claims.update(overrides)
    return {name: value for name, value in claims.items() if value is not ...}


def sign(
    key: SigningKey, claims: dict[str, object], *, headers: dict[str, object] | None = None
) -> str:
    return key.sign(claims, headers=headers)


# --- Per-test CPU budget (same rule as backend/tests/conftest.py, #51) ---
_CPU_LIMIT_SECONDS = float(os.environ.get("TEST_CPU_LIMIT", "1.0"))
_spent_key = pytest.StashKey[float]()


def _cpu_seconds() -> float:
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return time.process_time() + children.ru_utime + children.ru_stime


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Generator[None]:
    started = _cpu_seconds()
    try:
        return (yield)
    finally:
        item.stash[_spent_key] = _cpu_seconds() - started


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    spent = item.stash.get(_spent_key, None)
    if report.when == "call" and spent is not None:
        item.user_properties.append(("cpu_seconds", round(spent, 3)))
        report.user_properties.append(("cpu_seconds", round(spent, 3)))
        if _CPU_LIMIT_SECONDS > 0 and spent > _CPU_LIMIT_SECONDS and report.passed:
            report.outcome = "failed"
            report.longrepr = (
                f"시험 본문이 CPU {spent:.2f}초를 썼다 — 한도 {_CPU_LIMIT_SECONDS:g}초"
                " (TEST_CPU_LIMIT). 원인을 찾아 줄인다; 한도를 늘리지 않는다."
            )
    return report
