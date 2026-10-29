"""Signing keys, a fake JWKS and a frozen clock for the authkit tests. No network."""

import base64
import os
import resource
import time
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sandcorp_authkit.tokens import JwksCache

ISSUER = "https://auth.sandcorp.co.kr"
RESOURCE = "https://sandcorp.co.kr/mcp"
OWNER = "farrar142"
MEMBER = "m_01JB2Z3Y4X5W6V7T8S9R0Q1P2N"
START = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


class FrozenClock:
    def __init__(self, moment: datetime = START) -> None:
        self.moment = moment

    def now(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


@dataclass
class SigningKey:
    kid: str
    private: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    def jwk(self) -> dict[str, str]:
        raw = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "kid": self.kid,
            "alg": "EdDSA",
            "use": "sig",
        }


class FakeJwks:
    """The JWKS endpoint: serves `document`, counts fetches, fails while `failing` is set."""

    def __init__(self, *keys: SigningKey) -> None:
        self.document: object = {"keys": [key.jwk() for key in keys]}
        self.fetches = 0
        self.failing = False

    def serve(self, *keys: SigningKey) -> None:
        self.document = {"keys": [key.jwk() for key in keys]}

    def __call__(self) -> object:
        self.fetches += 1
        if self.failing:
            raise OSError("JWKS unreachable")
        return self.document


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


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
    return jwt.encode(
        claims, key.private, algorithm="EdDSA", headers=headers or {"kid": key.kid, "typ": "JWT"}
    )


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
