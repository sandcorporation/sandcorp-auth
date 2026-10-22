"""Request limiting on Postgres counters (no Redis).

Rules are named in `settings.THROTTLE` (`{"login": {"limit": 5, "window_seconds": 900,
"block_seconds": 900}, ...}`). A counter is keyed by `"<name>:<key>"`, e.g. `login:ip:1.2.3.4`.

- `check(name, key)`: may this key try now? (does not count)
- `hit(name, key)`: count one failure; reaching `limit` within the window blocks the key for
  `block_seconds`. Returns the decision after counting.
- `reset(name, key)`: forget the key (after a success).

`hit` locks the row with `select_for_update` inside a transaction, so concurrent failures are
counted one by one. Expired rows are reused; there is no cleanup job.
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


@dataclass(frozen=True)
class ThrottleDecision:
    allowed: bool
    retry_after: int  # seconds until the key may try again; 0 when allowed


ALLOWED = ThrottleDecision(allowed=True, retry_after=0)


def rule(name: str) -> ThrottleRule:
    raw: dict[str, int] = settings.THROTTLE[name]
    return ThrottleRule(
        limit=raw["limit"], window_seconds=raw["window_seconds"], block_seconds=raw["block_seconds"]
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


def hit(name: str, key: str) -> ThrottleDecision:
    limits = rule(name)
    full_key = f"{name}:{key}"
    now = get_clock().now()
    with transaction.atomic():
        ThrottleCounter.objects.bulk_create(
            [ThrottleCounter(key=full_key, window_started_at=now, count=0)],
            ignore_conflicts=True,
        )
        row = ThrottleCounter.objects.select_for_update().get(key=full_key)
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


def reset(name: str, key: str) -> None:
    ThrottleCounter.objects.filter(key=f"{name}:{key}").delete()
