"""Concurrent requests on real MySQL connections (#30).

The rest of the suite runs on one connection, one request at a time, so it cannot see races.
These tests start N threads at a barrier; each thread has its own DB connection and commits for
real (`transaction=True`). They pin what the single-row rules must hold under concurrency on
MySQL/InnoDB at READ COMMITTED: one active signing key, one live consent and one live refresh
token family (unique indexes over generated marker columns, since MySQL has no partial
indexes), one account per external identity (#35), throttle counters without deadlocks
(upsert, not INSERT IGNORE), one winner for an authorization code or a refresh token, and no
live refresh token family left on a consent revoked during a code exchange (#111), and no
deadlock between a code exchange and a withdrawal, a merge or a wider consent, or between a
refresh and a merge (#145, #151: the lock order of `services.locks`).
"""

import itertools
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from functools import partial
from typing import TYPE_CHECKING

import pytest
from django.contrib.auth.models import User
from django.db import IntegrityError, connection
from django.test import Client

from accounts.models import ExternalIdentity
from oauth.models import Client as OAuthClient
from oauth.models import Consent, RefreshTokenFamily, Resource, SigningKey, WebhookDelivery
from oauth.tokens import live_family
from services import audit, throttle
from services.consents import revoke_consent
from services.members import ExternalProfile, IdentityTaken, create_member
from services.merge import merge_member_into_owner
from services.signing import ActiveSigningKeyExists, create_signing_key
from services.social import SignInResult, link_identity, sign_in, unlink_identity
from services.webhooks import deliver_due, set_webhook
from services.withdrawal import withdraw_member
from tests.conftest import (
    PORTFOLIO,
    FakeWebhooks,
    FrozenClock,
    authorize_query,
    exchange_code,
    make_member,
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
ROUNDS = 5
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


def test_concurrent_sign_ups_with_one_identity_make_one_member() -> None:
    profile = ExternalProfile(provider="kakao", provider_sub="4242", display_name="동시")

    results = race(lambda: create_member(profile))

    winners = [r for r in results if isinstance(r, User)]
    losers = [r for r in results if not isinstance(r, User)]
    assert len(winners) == 1
    assert all(isinstance(r, IdentityTaken) for r in losers), losers
    assert ExternalIdentity.objects.count() == 1
    assert User.objects.count() == 1  # the losers' half-made accounts were rolled back


def test_concurrent_first_social_logins_sign_into_one_account() -> None:
    profile = ExternalProfile(provider="google", provider_sub="5151", display_name="동시")

    results = race(lambda: sign_in(profile, ip="127.0.0.1"))

    users = {r.user.pk for r in results if isinstance(r, SignInResult) and r.user is not None}
    assert len(users) == 1, results
    assert User.objects.count() == 1


def test_concurrent_unlinks_leave_the_last_login(db: None) -> None:
    for _ in range(ROUNDS // 4):
        User.objects.all().delete()
        user = create_member(ExternalProfile(provider="google", provider_sub="6161"))
        link_identity(user, ExternalProfile(provider="kakao", provider_sub="6262"), ip="")
        ids = list(ExternalIdentity.objects.filter(user=user).values_list("pk", flat=True))

        def unlink_one(user: User = user, ids: list[int] = ids) -> None:
            unlink_identity(user, ids.pop(), ip="")

        results = race(unlink_one, threads=2)

        assert sorted(type(r).__name__ for r in results) == ["LastIdentity", "NoneType"], results
        assert ExternalIdentity.objects.filter(user=user).count() == 1


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


def _exchange(oauth_client: OAuthClient, code: str, verifier: str) -> TestResponse:
    return exchange_code(Client(), oauth_client, code, verifier)


def test_an_authorization_code_is_exchanged_once(
    logged_in_client: Client, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    for _ in range(3):
        code, verifier = obtain_authorization_code(logged_in_client, dcr_client)

        results = race(partial(_exchange, dcr_client, code, verifier))

        assert all(not isinstance(r, BaseException) for r in results), results
        assert _successes(results) == 1


def test_a_refresh_token_is_rotated_once_and_every_racer_gets_the_successor(
    logged_in_client: Client, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    """An app's API calls refreshing together (#89): one rotation, the rest are within the
    grace and get the same successor; the family lives on."""
    from oauth.models import RefreshToken

    tokens = obtain_tokens(logged_in_client, dcr_client)
    token = str(tokens["refresh_token"])

    results = race(lambda: refresh(Client(), dcr_client, token))

    assert all(not isinstance(r, BaseException) for r in results), results
    assert _successes(results) == THREADS
    successors = {r.json()["refresh_token"] for r in results if not isinstance(r, BaseException)}
    assert len(successors) == 1
    assert RefreshToken.objects.count() == 2
    assert RefreshTokenFamily.objects.get().revoked_at is None
    assert refresh(Client(), dcr_client, successors.pop()).status_code == 200


def _take_turn(jobs: Sequence[Callable[[], object]], turn: itertools.count[int]) -> object:
    return jobs[next(turn)]()


def test_a_consent_revoked_during_a_code_exchange_keeps_no_live_family(
    logged_in_client: Client, owner: User, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    for _ in range(ROUNDS):
        code, verifier = obtain_authorization_code(logged_in_client, dcr_client)
        consent = Consent.objects.select_related("client", "resource").get(
            user=owner, revoked_at__isnull=True
        )
        jobs: list[Callable[[], object]] = [
            partial(_exchange, dcr_client, code, verifier),
            partial(revoke_consent, consent, reason="consent_revoked", actor="admin", ip=""),
        ]
        turn = itertools.count()

        results = race(partial(_take_turn, jobs, turn), threads=2)

        assert all(not isinstance(r, BaseException) for r in results), results
        assert Consent.objects.get(pk=consent.pk).revoked_at is not None
        assert not RefreshTokenFamily.objects.filter(consent=consent, revoked_at=None).exists()


def test_concurrent_withdrawals_withdraw_once_and_queue_one_webhook(
    dcr_client: OAuthClient, fake_webhooks: FakeWebhooks
) -> None:
    from audit.models import AuditEvent

    member = make_member()
    set_webhook(dcr_client, url="https://site.example/hook", rotate_secret=False, actor="t")
    Consent.objects.create(
        user=member,
        client=dcr_client,
        resource=Resource.objects.get(url=PORTFOLIO),
        scopes=["login"],
        granted_at=NOW,
    )

    results = race(lambda: withdraw_member(User.objects.get(pk=member.pk)))

    assert results.count(True) == 1 and results.count(False) == THREADS - 1, results
    assert AuditEvent.objects.filter(kind=audit.MEMBER_WITHDRAWN).count() == 1
    assert WebhookDelivery.objects.count() == 1

    reports = race(deliver_due)
    assert sum(r.delivered for r in reports if not isinstance(r, BaseException)) == 1, reports
    assert len(fake_webhooks.sent) == 1


def _member_code(oauth_client: OAuthClient, provider_sub: str) -> tuple[User, str, str]:
    member = make_member("kakao", provider_sub)
    browser = Client()
    browser.force_login(member)
    code, verifier = obtain_authorization_code(browser, oauth_client, scope="login")
    return member, code, verifier


def _exchange_status(oauth_client: OAuthClient, code: str, verifier: str) -> int:
    return _exchange(oauth_client, code, verifier).status_code


def test_a_code_exchange_racing_a_withdrawal_or_a_merge_ends_without_deadlock(
    owner: User, dcr_client: OAuthClient, signing_key: SigningKey, frozen_clock: FrozenClock
) -> None:
    """#145: the exchange locks the account before the consent, as a withdrawal and a merge do;
    the other order deadlocked (one side rolled back). Either the exchange comes first (and its
    family is revoked) or it waits and is refused."""
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    for index in range(ROUNDS):
        member, code, verifier = _member_code(dcr_client, f"91{index}")
        if index % 2:
            other: Callable[[], object] = partial(
                merge_member_into_owner, member.username, owner.username
            )
        else:
            other = partial(withdraw_member, User.objects.get(pk=member.pk))
        jobs: list[Callable[[], object]] = [
            partial(_exchange_status, dcr_client, code, verifier),
            other,
        ]

        results = race(partial(_take_turn, jobs, itertools.count()), threads=2)

        assert all(not isinstance(r, BaseException) for r in results), results
        assert [r for r in results if isinstance(r, int) and not isinstance(r, bool)] in (
            [200],
            [400],
        ), results
        assert not RefreshTokenFamily.objects.filter(user=member, revoked_at=None).exists()
        ExternalIdentity.objects.filter(user=owner).delete()


def _status(response: TestResponse) -> int:
    return response.status_code


def _refresh_status(oauth_client: OAuthClient, token: str) -> int:
    return refresh(Client(), oauth_client, token).status_code


def test_a_code_exchange_racing_a_wider_consent_ends_without_deadlock(
    logged_in_client: Client, owner: User, dcr_client: OAuthClient, signing_key: SigningKey
) -> None:
    """#151: allowing a wider consent replaces the old one (revokes it, inserts the new one)
    while a code under the old one is exchanged. Both lock the account first; the other order
    deadlocked (one side answered 500)."""
    wider = "/authorize?" + authorize_query(dcr_client, scope="admin login")
    for _ in range(ROUNDS):
        for live in Consent.objects.filter(user=owner, revoked_at__isnull=True):
            revoke_consent(live, reason="consent_revoked", actor="t", ip="")
        code, verifier = obtain_authorization_code(logged_in_client, dcr_client)
        jobs: list[Callable[[], object]] = [
            partial(_exchange_status, dcr_client, code, verifier),
            lambda: _status(logged_in_client.post(wider, {"decision": "allow"})),
        ]

        results = race(partial(_take_turn, jobs, itertools.count()), threads=2)

        assert all(not isinstance(r, BaseException) for r in results), results
        statuses = sorted(r for r in results if isinstance(r, int))
        assert statuses in ([200, 302], [302, 400]), results
        revoked = Consent.objects.filter(user=owner, revoked_at__isnull=False)
        assert not RefreshTokenFamily.objects.filter(consent__in=revoked, revoked_at=None).exists()


def test_a_refresh_racing_a_merge_ends_without_deadlock(
    owner: User, dcr_client: OAuthClient, signing_key: SigningKey, frozen_clock: FrozenClock
) -> None:
    """#151: a merge revokes the member's families and deletes its tokens while its app
    rotates a refresh token. Both lock the account first; the other order deadlocked."""
    OAuthClient.objects.filter(pk=dcr_client.pk).update(allows_members=True)
    dcr_client.refresh_from_db()
    for index in range(ROUNDS):
        member, code, verifier = _member_code(dcr_client, f"92{index}")
        response = _exchange(dcr_client, code, verifier)
        assert response.status_code == 200, response.content
        token = str(response.json()["refresh_token"])
        jobs: list[Callable[[], object]] = [
            partial(_refresh_status, dcr_client, token),
            partial(merge_member_into_owner, member.username, owner.username),
        ]

        results = race(partial(_take_turn, jobs, itertools.count()), threads=2)

        assert all(not isinstance(r, BaseException) for r in results), results
        assert [r for r in results if isinstance(r, int)] in ([200], [400]), results
        assert not User.objects.filter(pk=member.pk).exists()
        assert not RefreshTokenFamily.objects.filter(user=owner, revoked_at=None).exists()
        ExternalIdentity.objects.filter(user=owner).delete()
