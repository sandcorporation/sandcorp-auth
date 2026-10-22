"""Signing keys end to end: the management command creates/rotates keys, the JWKS publishes
them, and tokens from the issuance service pass the reference validator (frozen clock)."""

from collections.abc import Callable

import jwt
import pytest
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import Client

from services.signing import NoActiveSigningKey
from services.tokens import issue_access_token
from tests.conftest import FrozenClock, RecordingRandomness
from tests.reference_validator import (
    AccessToken,
    JwksCache,
    JwkSet,
    TokenRejected,
    validate_access_token,
)

NEWS = "https://news.sandcorp.co.kr/mcp"
PORTFOLIO = "https://sandcorp.co.kr/mcp"
OWNER = "owner"

pytestmark = pytest.mark.django_db


def jwks_fetcher(client: Client) -> Callable[[], JwkSet]:
    def fetch() -> JwkSet:
        jwk_set: JwkSet = client.get("/.well-known/jwks.json").json()
        return jwk_set

    return fetch


def jwks_kids(client: Client) -> list[str]:
    return [key["kid"] for key in jwks_fetcher(client)()["keys"]]


def issue(audience: str = NEWS) -> str:
    return issue_access_token(
        sub=OWNER, audience=audience, client_id="client-1", scopes=["admin", "editor"]
    )


def validate(token: str, cache: JwksCache, clock: FrozenClock, audience: str = NEWS) -> AccessToken:
    return validate_access_token(
        token, jwks=cache, audience=audience, owner_sub=OWNER, required_scope="admin", clock=clock
    )


def kid_of(token: str) -> str:
    kid = jwt.get_unverified_header(token)["kid"]
    assert isinstance(kid, str)
    return kid


def test_created_key_is_published_and_signs_tokens_the_validator_accepts(
    client: Client, frozen_clock: FrozenClock
) -> None:
    call_command("signing_keys", "create")

    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response["Cache-Control"] == "public, max-age=600"
    [jwk] = response.json()["keys"]
    assert {k: jwk[k] for k in ("kty", "crv", "alg", "use")} == {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
    }

    token = issue()
    assert kid_of(token) == jwk["kid"]
    cache = JwksCache(jwks_fetcher(client), frozen_clock)
    access = validate(token, cache, frozen_clock)
    assert access.sub == OWNER
    assert access.client_id == "client-1"
    assert access.scopes == frozenset({"admin", "editor"})
    assert access.exp - access.iat == 600

    with pytest.raises(TokenRejected, match="audience"):
        validate(token, cache, frozen_clock, audience=PORTFOLIO)


def test_token_expires_after_ten_minutes(client: Client, frozen_clock: FrozenClock) -> None:
    call_command("signing_keys", "create")
    token = issue()
    cache = JwksCache(jwks_fetcher(client), frozen_clock)

    frozen_clock.advance(630)  # exp + the validator's 30 s leeway: still accepted
    validate(token, cache, frozen_clock)

    frozen_clock.advance(1)
    with pytest.raises(TokenRejected, match="expired"):
        validate(token, cache, frozen_clock)


def test_rotation_keeps_the_old_key_published_for_the_token_lifetime(
    client: Client, frozen_clock: FrozenClock
) -> None:
    call_command("signing_keys", "create")
    old_token = issue()
    cache = JwksCache(jwks_fetcher(client), frozen_clock)
    validate(old_token, cache, frozen_clock)

    frozen_clock.advance(60)
    call_command("signing_keys", "rotate")
    new_token = issue()

    assert kid_of(new_token) != kid_of(old_token)
    assert jwks_kids(client) == [kid_of(new_token), kid_of(old_token)]
    validate(new_token, cache, frozen_clock)
    validate(old_token, cache, frozen_clock)

    frozen_clock.advance(600)
    assert jwks_kids(client) == [kid_of(new_token), kid_of(old_token)]

    frozen_clock.advance(1)
    assert jwks_kids(client) == [kid_of(new_token)]


def test_create_refuses_when_a_key_is_active(client: Client, frozen_clock: FrozenClock) -> None:
    call_command("signing_keys", "create")

    with pytest.raises(CommandError, match="rotate") as excinfo:
        call_command("signing_keys", "create")

    assert excinfo.value.returncode == 1
    assert len(jwks_kids(client)) == 1


def test_list_shows_keys_with_state(
    capsys: pytest.CaptureFixture[str], frozen_clock: FrozenClock
) -> None:
    call_command("signing_keys", "create")
    frozen_clock.advance(60)
    call_command("signing_keys", "rotate")
    capsys.readouterr()

    call_command("signing_keys", "list")

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["kid", "state", "created_at", "retired_at"]
    assert [line.split()[1] for line in lines[1:]] == ["active", "retired"]
    assert lines[1].split()[3] == "-"
    assert lines[2].split()[3] == "2026-01-01T00:01:00+00:00"


def test_no_keys_means_empty_jwks_and_issuance_fails(client: Client) -> None:
    assert client.get("/.well-known/jwks.json").json() == {"keys": []}

    with pytest.raises(NoActiveSigningKey):
        issue()


def test_private_key_is_not_stored_in_the_clear(
    recording_randomness: RecordingRandomness,
) -> None:
    call_command("signing_keys", "create")

    [seed] = [raw for raw in recording_randomness.issued if len(raw) == 32]
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM oauth_signingkey")
        [row] = cursor.fetchall()
    stored = b"".join(
        bytes(value) if isinstance(value, memoryview) else str(value).encode() for value in row
    )
    assert seed not in stored
    assert seed.hex().encode() not in stored
