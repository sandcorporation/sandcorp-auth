"""Clock adapter: the one place services ask "what time is it".

Services call `get_clock().now()` instead of `datetime.now()` so tests can freeze time
(tests/conftest.py `frozen_clock`). `now()` is always timezone-aware UTC.
"""

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


_clock: Clock = SystemClock()


def get_clock() -> Clock:
    return _clock


def set_clock(clock: Clock) -> Clock:
    """Install `clock` and return the previous one so callers can restore it."""
    global _clock
    previous, _clock = _clock, clock
    return previous
