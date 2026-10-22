"""Request limiting on Postgres counters (no Redis).

Rules are named in `settings.THROTTLE` (`{"login": {"limit": 5, "window_seconds": 900,
"block_seconds": 900}, ...}`). A counter is keyed by `"<name>:<key>"`, e.g. `login:ip:1.2.3.4`.

- `check(name, key)`: may this key try now? (does not count)
- `hit(name, key)`: count one failure; reaching `limit` within the window blocks the key for
  `block_seconds`. Returns the decision after counting.
- `reset(name, key)`: forget the key (after a success).

`hit` locks the row with `select_for_update` inside a transaction, so concurrent failures are
counted one by one. Expired rows are reused; there is no cleanup job.

A rule with `"mode": "backoff"` (`{"mode": "backoff", "max_delay_seconds": 60,
"window_seconds": 900}`) delays instead of blocking: `backoff_hit(name, key)` records the n-th
consecutive failure and refuses the key for `min(max_delay_seconds, 2 ** (n - 1))` seconds
(`count` holds n, `blocked_until` the next allowed moment, `window_started_at` the last failure).
After `window_seconds` without a failure n starts over. `check` and `reset` serve both modes.
Nothing sleeps: a refused request is answered at once with `retry_after`.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TypedDict

from django.conf import settings
from django.db import transaction

from adapters.clock import get_clock
from core.models import ThrottleCounter


class ThrottleRule(TypedDict):
    limit: int
    window_seconds: int
    block_seconds: int


class BackoffRule(TypedDict):
    max_delay_seconds: int
    window_seconds: int


@dataclass(frozen=True)
class ThrottleDecision:
    allowed: bool
    retry_after: int  # seconds until the key may try again; 0 when allowed


ALLOWED = ThrottleDecision(allowed=True, retry_after=0)


def rule(name: str) -> ThrottleRule:
    raw: dict[str, int | str] = settings.THROTTLE[name]
    return ThrottleRule(
        limit=int(raw["limit"]),
        window_seconds=int(raw["window_seconds"]),
        block_seconds=int(raw["block_seconds"]),
    )


def backoff_rule(name: str) -> BackoffRule:
    raw: dict[str, int | str] = settings.THROTTLE[name]
    if raw.get("mode") != "backoff":
        raise ValueError(f"throttle rule {name!r} is not a backoff rule")
    return BackoffRule(
        max_delay_seconds=int(raw["max_delay_seconds"]), window_seconds=int(raw["window_seconds"])
    )


def _blocked(blocked_until: datetime | None, now: datetime) -> ThrottleDecision:
    if blocked_until is None or blocked_until <= now:
        return ALLOWED
    return ThrottleDecision(
        allowed=False, retry_after=math.ceil((blocked_until - now).total_seconds())
    )


def check(name: str, key: str) -> ThrottleDecision:
    row = ThrottleCounter.objects.filter(key=f"{name}:{key}").first()
    if row is None:
        return ALLOWED
    return _blocked(row.blocked_until, get_clock().now())


def _locked_row(full_key: str, now: datetime) -> ThrottleCounter:
    """The counter row for `full_key`, created if missing and locked until the transaction ends."""
    ThrottleCounter.objects.bulk_create(
        [ThrottleCounter(key=full_key, window_started_at=now, count=0)],
        ignore_conflicts=True,
    )
    return ThrottleCounter.objects.select_for_update().get(key=full_key)


def hit(name: str, key: str) -> ThrottleDecision:
    limits = rule(name)
    full_key = f"{name}:{key}"
    now = get_clock().now()
    with transaction.atomic():
        row = _locked_row(full_key, now)
        current = _blocked(row.blocked_until, now)
        if not current.allowed:
            return current
        window_over = row.window_started_at + timedelta(seconds=limits["window_seconds"]) <= now
        if window_over or row.blocked_until is not None:
            row.window_started_at, row.count, row.blocked_until = now, 0, None
        row.count += 1
        if row.count >= limits["limit"]:
            row.blocked_until = now + timedelta(seconds=limits["block_seconds"])
        row.save()
        return _blocked(row.blocked_until, now)


def backoff_hit(name: str, key: str) -> ThrottleDecision:
    """Count one consecutive failure of a backoff rule; the delay it starts (never allowed).
    A hit that arrives while the key is still delayed is not counted (the caller should have
    asked `check` first; this only happens to racing requests)."""
    limits = backoff_rule(name)
    full_key = f"{name}:{key}"
    now = get_clock().now()
    with transaction.atomic():
        row = _locked_row(full_key, now)
        current = _blocked(row.blocked_until, now)
        if not current.allowed:
            return current
        if row.window_started_at + timedelta(seconds=limits["window_seconds"]) <= now:
            row.count = 0
        row.count += 1
        delay = min(limits["max_delay_seconds"], 2 ** (row.count - 1))
        row.window_started_at, row.blocked_until = now, now + timedelta(seconds=delay)
        row.save()
        return ThrottleDecision(allowed=False, retry_after=delay)


def reset(name: str, key: str) -> None:
    ThrottleCounter.objects.filter(key=f"{name}:{key}").delete()
