"""Behind a proxy that appends (`X-Forwarded-For: <client sent>, <real peer>`), a forged first
entry must not give each request a fresh IP: the per-IP login lock still catches the caller."""

import pytest
from django.contrib.auth.models import User
from django.test import Client, RequestFactory, override_settings

from config.settings import trusted_proxy_count
from core.http import client_ip
from tests.conftest import OWNER_PASSWORD, OWNER_USERNAME, FrozenClock

LOCKED = "뒤 다시 시도하세요"
REAL = "203.0.113.7"  # the caller, as the proxy saw it
PROXY = "172.17.0.1"  # REMOTE_ADDR: the proxy itself


def post(client: Client, username: str, password: str, forged: str) -> str:
    response = client.post(
        "/login",
        {"username": username, "password": password},
        REMOTE_ADDR=PROXY,
        HTTP_X_FORWARDED_FOR=f"{forged}, {REAL}",
    )
    return response.content.decode()


@pytest.mark.django_db
def test_forged_forwarded_for_does_not_escape_the_ip_lock(
    client: Client, owner: User, frozen_clock: FrozenClock
) -> None:
    with override_settings(TRUST_X_FORWARDED_FOR=1):
        for n, name in enumerate(["alice", "bob", "carol", "dave", "erin"]):
            post(client, name, "wrong password!!", forged=f"198.51.100.{n}")
        body = post(client, OWNER_USERNAME, OWNER_PASSWORD, forged="198.51.100.99")
    assert LOCKED in body


def ip_for(forwarded: str | None, hops: int, remote: str = PROXY) -> str:
    meta = {"REMOTE_ADDR": remote}
    if forwarded is not None:
        meta["HTTP_X_FORWARDED_FOR"] = forwarded
    with override_settings(TRUST_X_FORWARDED_FOR=hops):
        return client_ip(RequestFactory().get("/", **meta))


@pytest.mark.parametrize(
    ("forwarded", "hops", "expected"),
    [
        # One proxy: the entry it appended, whatever the caller put before it.
        (f"198.51.100.1, {REAL}", 1, REAL),
        (REAL, 1, REAL),
        # Two proxies: the outer one's entry; the inner one's own entry is ignored.
        (f"198.51.100.1, {REAL}, 10.0.0.2", 2, REAL),
        (f"{REAL}, 10.0.0.2", 2, REAL),
        # Too few entries for the trusted hops: the direct peer.
        (REAL, 2, PROXY),
        (None, 1, PROXY),
        ("", 1, PROXY),
        (" , ,", 1, PROXY),
        # Spaces and empty items are skipped before counting.
        (f"198.51.100.1,,  {REAL} ,", 1, REAL),
        # IPv6, bare or in brackets.
        ("198.51.100.1, 2001:db8::7", 1, "2001:db8::7"),
        ("[2001:db8::7]", 1, "2001:db8::7"),
        # Not an address: the direct peer.
        ("198.51.100.1, unknown", 1, PROXY),
        # 0: X-Forwarded-For is ignored.
        (f"198.51.100.1, {REAL}", 0, PROXY),
    ],
)
def test_client_ip_counts_trusted_proxies_from_the_right(
    forwarded: str | None, hops: int, expected: str
) -> None:
    assert ip_for(forwarded, hops) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1", 1), ("2", 2), ("0", 0), ("true", 1), ("True", 1), (" 1 ", 1), ("false", 0), ("", 0)],
)
def test_setting_reads_old_and_new_spellings(raw: str, expected: int) -> None:
    assert trusted_proxy_count(raw) == expected
