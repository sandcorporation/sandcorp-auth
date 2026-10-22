"""Shared fixtures for backend HTTP-boundary tests.

Fake adapters get registered here as they appear: `frozen_clock`, `recording_randomness`.
`signing_key` gives a test an active token signing key.
"""

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest

from adapters.clock import set_clock
from adapters.randomness import set_randomness
from oauth.models import SigningKey
from services.signing import create_signing_key


class FrozenClock:
    """A clock that only moves when the test says so."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


@pytest.fixture
def frozen_clock() -> Iterator[FrozenClock]:
    """Freeze `get_clock().now()` at 2026-01-01T00:00:00Z; `advance(seconds)` moves it."""
    clock = FrozenClock(datetime(2026, 1, 1, tzinfo=UTC))
    previous = set_clock(clock)
    yield clock
    set_clock(previous)


class RecordingRandomness:
    """Deterministic, distinct bytes per call; remembers everything it handed out."""

    def __init__(self) -> None:
        self.issued: list[bytes] = []

    def token_bytes(self, n: int) -> bytes:
        block = hashlib.sha256(len(self.issued).to_bytes(4, "big")).digest()
        out = (block * (n // len(block) + 1))[:n]
        self.issued.append(out)
        return out


@pytest.fixture
def recording_randomness() -> Iterator[RecordingRandomness]:
    """Install a deterministic randomness source whose outputs the test can inspect."""
    randomness = RecordingRandomness()
    previous = set_randomness(randomness)
    yield randomness
    set_randomness(previous)


@pytest.fixture
def signing_key(db: None) -> SigningKey:
    """An active signing key (same as `manage.py signing_keys create`)."""
    return create_signing_key()
