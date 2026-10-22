"""Shared fixtures for backend HTTP-boundary tests.

Fake adapters get registered here as they appear (clock below; randomness when a test needs it).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest

from adapters.clock import set_clock


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
