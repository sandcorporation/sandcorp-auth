"""Concurrent requests on real MySQL connections (#30).

The rest of the suite runs on one connection, one request at a time, so it cannot see races.
These tests start N threads at a barrier; each thread has its own DB connection and commits for
real (`transaction=True`). They pin what the single-row rules must hold under concurrency on
MySQL/InnoDB at READ COMMITTED: one active signing key, one live consent and one live refresh
token family (unique indexes over generated marker columns, since MySQL has no partial
indexes), throttle counters without deadlocks (upsert, not INSERT IGNORE), and one winner for an
authorization code or a refresh token.
"""

import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from functools import partial
from typing import TYPE_CHECKING

import pytest
from django.contrib.auth.models import User
from django.db import IntegrityError, connection
from django.test import Client

from oauth.models import Client as OAuthClient
from oauth.models import Consent, RefreshTokenFamily, Resource, SigningKey
from oauth.tokens import live_family
from services import throttle
from services.signing import ActiveSigningKeyExists, create_signing_key
from tests.conftest import (
    PORTFOLIO,
    FrozenClock,
    exchange_code,
    obtain_authorization_code,
    obtain_tokens,
    refresh,
)

# serialized_rollback: the flush after each test would wipe the resources and scopes that
# migrations seed; restore them for the next test.
if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as TestResponse

pytestmark = pytest.mark.django_db(transaction=True, serialized_rollback=True)

THREADS = 8
ROUNDS = 20
NOW = datetime(2026, 10, 23, 9, 0, tzinfo=UTC)


def race[T](work: Callable[[], T], threads: int = THREADS) -> list[T | BaseException]:
    """Run `work` in `threads` threads released together; each result or raised exception."""
    barrier = threading.Barrier(threads)
    results: list[T | BaseException] = [RuntimeError("did not run")] * threads

    def run(index: int) -> None:
        try:
            barrier.wait(timeout=10)
            results[index] = work()
        except BaseException as error:  # the test inspects every outcome
            results[index] = error
        finally:
            connection.close()

    workers = [threading.Thread(target=run, args=(i,)) for i in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=60)
    return results


def test_concurrent_signing_key_creation_leaves_one_active_key() -> None:
    results = race(create_signing_key)

    winners = [r for r in results if isinstance(r, SigningKey)]
    losers = [r for r in results if not isinstance(r, SigningKey)]
    assert len(winners) == 1
    assert all(isinstance(r, ActiveSigningKeyExists | IntegrityError) for r in losers), losers
    assert SigningKey.objects.filter(active=True).count() == 1


def _consent(owner: User, oauth_client: OAuthClient, resource: Resource) -> Consent:
    return Consent.objects.create(
        user=owner, client=oauth_client, resource=resource, scopes=["admin"], granted_at=NOW
    )


def test_concurrent_consents_leave_one_live_consent(owner: User, dcr_client: OAuthClient) -> None:
    resource = Resource.objects.get(url=PORTFOLIO)

    results = race(lambda: _consent(owner, dcr_client, resource))

    assert sum(isinstance(r, Consent) for r in results) == 1
    assert sum(isinstance(r, IntegrityError) for r in results) == THREADS - 1
    assert Consent.objects.filter(revoked_at__isnull=True).count() == 1
    # A revoked consent no longer counts: a new live one fits beside it.
    Consent.objects.update(revoked_at=NOW)
    _consent(owner, dcr_client, resource)
    assert Consent.objects.count() == 2


def test_concurrent_first_use_opens_one_live_family(
    owner: User, dcr_client: OAuthClient, frozen_clock: FrozenClock
) -> None:
    resource = Resource.objects.get(url=PORTFOLIO)
    for _ in range(ROUNDS):
        Consent.objects.filter(revoked_at__isnull=True).update(revoked_at=NOW)
        consent = _consent(owner, dcr_client, resource)

        results = race(partial(live_family, consent))

        assert all(isinstance(r, RefreshTokenFamily) for r in results), results
        assert len({r.pk for r in results if isinstance(r, RefreshTokenFamily)}) == 1
        assert RefreshTokenFamily.objects.filter(consent=consent, revoked_at=None).count() == 1


def test_concurrent_failures_on_one_key_are_counted_without_deadlocks(
    frozen_clock: FrozenClock,
) -> None:
    limit = throttle.rule("login")["limit"]
    for round_ in range(ROUNDS):
        key = f"ip:203.0.113.{round_}"

        results = race(partial(throttle.hit, "login", key))

        decisions = [r for r in results if isinstance(r, throttle.ThrottleDecision)]
        assert len(decisions) == THREADS, [r for r in results if r not in decisions]
        # Same as one at a time: limit - 1 failures allowed, the limit-th and later blocked.
        assert sum(d.allowed for d in decisions) == limit - 1
        assert not throttle.check("login", key).allowed


def _successes(results: Sequence[object]) -> int:
    return sum(getattr(r, "status_code", None) == 200 for r in results)


def _exchange(oauth_client: OAuthClient, code: str, verifier: str) -> "TestResponse":
    return exchange_code(Client(), oauth_client, code, verifier)


def test_an_authorization_code_is_exchanged_once(
    logged_in_client: Client, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    for _ in range(3):
        code, verifier = obtain_authorization_code(logged_in_client, dcr_client)

        results = race(partial(_exchange, dcr_client, code, verifier))

        assert all(not isinstance(r, BaseException) for r in results), results
        assert _successes(results) == 1


def test_a_refresh_token_is_rotated_once(
    logged_in_client: Client, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    tokens = obtain_tokens(logged_in_client, dcr_client)
    token = str(tokens["refresh_token"])

    results = race(lambda: refresh(Client(), dcr_client, token))

    assert all(not isinstance(r, BaseException) for r in results), results
    assert _successes(results) == 1
