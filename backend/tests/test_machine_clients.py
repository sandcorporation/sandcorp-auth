"""Machine clients (#76): `clients create-machine`, `grant_type=client_credentials` for them only,
tokens bound to the client's resource and scopes, `sub=client:<id>`, `acct=machine`."""

import io
from datetime import timedelta

import jwt
import pytest
from django.contrib.auth.hashers import check_password
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client

from audit.models import AuditEvent
from oauth.models import Client as OAuthClient
from oauth.models import Resource, Scope, SigningKey
from services.confidential_clients import IssuedClient, create_confidential_client
from services.machine_clients import UnknownResource, UnknownScope, create_machine_client
from tests.conftest import NEWS, OWNER_USERNAME, PORTFOLIO, FrozenClock, use_https
from tests.reference_validator import (
    JwksCache,
    TokenRejected,
    validate_access_token,
    validate_account_access_token,
    validate_machine_access_token,
)
from tests.test_confidential_clients import basic, post_token
from tests.test_signing_keys import jwks_fetcher

pytestmark = pytest.mark.django_db

PROMPTLAB = "https://promptlab.sandcorp.co.kr/api"


@pytest.fixture
def promptlab(db: None) -> Resource:
    resource = Resource.objects.create(name="promptlab", url=PROMPTLAB)
    for name in ("smoke.submit", "exam.read", "admin"):
        Scope.objects.create(resource=resource, name=name, description=name)
    return resource


@pytest.fixture
def machine(promptlab: Resource, signing_key: SigningKey) -> IssuedClient:
    return create_machine_client(
        "promptlab 스모크", PROMPTLAB, ["smoke.submit", "exam.read"], actor="test"
    )


def credentials_form(**extra: str) -> dict[str, str | None]:
    return {"grant_type": "client_credentials", **extra}


def test_machine_client_gets_a_token_with_basic_auth(
    client: Client, machine: IssuedClient, frozen_clock: FrozenClock
) -> None:
    response = post_token(
        client, credentials_form(), basic(machine.client.client_id, machine.secret)
    )

    assert response.status_code == 200, response.content
    assert response["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {"access_token", "token_type", "expires_in", "scope"}  # no refresh
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 600
    assert body["scope"] == "exam.read smoke.submit"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert set(claims) == {"iss", "sub", "aud", "client_id", "scope", "iat", "exp", "jti", "acct"}
    assert claims["sub"] == f"client:{machine.client.client_id}"
    assert claims["acct"] == "machine"
    assert claims["aud"] == PROMPTLAB
    assert claims["client_id"] == machine.client.client_id
    assert claims["exp"] - claims["iat"] == 600
    verified = validate_machine_access_token(
        body["access_token"],
        jwks=JwksCache(jwks_fetcher(client), frozen_clock),
        audience=PROMPTLAB,
        machine_client_ids=frozenset({machine.client.client_id}),
        required_scope="smoke.submit",
        clock=frozen_clock,
    )
    assert verified.acct == "machine"
    event = AuditEvent.objects.filter(kind="token.issued").get()
    assert event.actor == f"client:{machine.client.client_id}"


def test_machine_client_with_post_auth_narrower_scope_and_its_resource(
    client: Client, machine: IssuedClient
) -> None:
    form = credentials_form(
        client_id=machine.client.client_id,
        client_secret=machine.secret,
        scope="smoke.submit",
        resource=PROMPTLAB,
    )
    response = post_token(client, form)

    assert response.status_code == 200, response.content
    assert response.json()["scope"] == "smoke.submit"


def test_machine_token_is_refused_by_owner_and_member_validators(
    client: Client, machine: IssuedClient, frozen_clock: FrozenClock
) -> None:
    token = post_token(
        client, credentials_form(), basic(machine.client.client_id, machine.secret)
    ).json()["access_token"]
    jwks = JwksCache(jwks_fetcher(client), frozen_clock)

    with pytest.raises(TokenRejected):  # T11: sub is not the owner
        validate_access_token(
            token,
            jwks=jwks,
            audience=PROMPTLAB,
            owner_sub=OWNER_USERNAME,
            required_scope="smoke.submit",
            clock=frozen_clock,
        )
    with pytest.raises(TokenRejected):  # A2: acct is not "member"
        validate_account_access_token(
            token,
            jwks=jwks,
            audience=PROMPTLAB,
            owner_sub=OWNER_USERNAME,
            required_scope="smoke.submit",
            clock=frozen_clock,
        )
    with pytest.raises(TokenRejected):  # M3: a client the site does not know
        validate_machine_access_token(
            token,
            jwks=jwks,
            audience=PROMPTLAB,
            machine_client_ids=frozenset({"someone-else"}),
            required_scope="smoke.submit",
            clock=frozen_clock,
        )


def test_wrong_secret_is_401(client: Client, machine: IssuedClient) -> None:
    response = post_token(client, credentials_form(), basic(machine.client.client_id, "nope"))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_inactive_machine_client_is_refused(client: Client, machine: IssuedClient) -> None:
    OAuthClient.objects.filter(pk=machine.client.pk).update(active=False)

    response = post_token(
        client, credentials_form(), basic(machine.client.client_id, machine.secret)
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        ({"scope": "admin"}, "invalid_scope"),  # the resource's, but not bound to the client
        ({"scope": "smoke.submit nope"}, "invalid_scope"),
        ({"resource": PORTFOLIO}, "invalid_target"),
        ({"resource": "https://elsewhere.example/api"}, "invalid_target"),
    ],
)
def test_unbound_resource_or_scope_is_refused(
    client: Client, machine: IssuedClient, extra: dict[str, str], error: str
) -> None:
    response = post_token(
        client, credentials_form(**extra), basic(machine.client.client_id, machine.secret)
    )

    assert response.status_code == 400
    assert response.json()["error"] == error


def test_two_resources_are_refused(client: Client, machine: IssuedClient) -> None:
    use_https(client)
    response = client.post(
        "/token",
        {"grant_type": "client_credentials", "resource": [PROMPTLAB, NEWS]},
        HTTP_AUTHORIZATION=basic(machine.client.client_id, machine.secret),
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_target"


def test_scope_deleted_from_the_resource_is_dropped(client: Client, machine: IssuedClient) -> None:
    Scope.objects.filter(resource__url=PROMPTLAB, name="exam.read").delete()

    response = post_token(
        client, credentials_form(), basic(machine.client.client_id, machine.secret)
    )

    assert response.json()["scope"] == "smoke.submit"


def test_confidential_client_is_refused(client: Client, signing_key: SigningKey) -> None:
    issued = create_confidential_client("관리", ["https://sandcorp.co.kr/cb"], actor="test")

    response = post_token(client, credentials_form(), basic(issued.client.client_id, issued.secret))

    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"


@pytest.mark.parametrize("fixture", ["dcr_client", "cimd_client"])
def test_public_clients_are_refused(
    client: Client, request: pytest.FixtureRequest, fixture: str
) -> None:
    public: OAuthClient = request.getfixturevalue(fixture)

    response = post_token(client, credentials_form(client_id=public.client_id))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


@pytest.mark.parametrize(
    "form",
    [
        {"grant_type": "authorization_code", "code": "c", "code_verifier": "v"},
        {"grant_type": "refresh_token", "refresh_token": "r"},
    ],
)
def test_machine_client_has_no_other_grant(
    client: Client, machine: IssuedClient, form: dict[str, str | None]
) -> None:
    response = post_token(client, form, basic(machine.client.client_id, machine.secret))

    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"


def test_machine_client_cannot_start_the_code_flow(
    logged_in_client: Client, machine: IssuedClient
) -> None:
    use_https(logged_in_client)
    response = logged_in_client.get(
        "/authorize",
        {
            "response_type": "code",
            "client_id": machine.client.client_id,
            "redirect_uri": "https://promptlab.sandcorp.co.kr/cb",
            "scope": "smoke.submit",
            "resource": PROMPTLAB,
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )

    assert response.status_code == 400  # no redirect URI: shown here, never redirected


def test_create_machine_command_prints_the_secret_once(promptlab: Resource) -> None:
    out = io.StringIO()
    call_command(
        "clients",
        "create-machine",
        "--name",
        "promptlab 스모크",
        "--resource",
        PROMPTLAB,
        "--scope",
        "smoke.submit exam.read",
        stdout=out,
    )

    created = OAuthClient.objects.get(kind=OAuthClient.Kind.MACHINE)
    lines = dict(line.split(": ", 1) for line in out.getvalue().splitlines() if ": " in line)
    assert lines["client_id"] == created.client_id
    assert check_password(lines["client_secret"], created.secret_hash)
    assert lines["resource"] == PROMPTLAB
    assert lines["scope"] == "exam.read smoke.submit"
    assert created.machine_resource == promptlab
    assert created.machine_scopes == ["exam.read", "smoke.submit"]
    assert created.redirect_uris == []
    assert lines["client_secret"] not in created.secret_hash

    listed = io.StringIO()
    call_command("clients", "list", stdout=listed)
    row = listed.getvalue().strip()
    assert row.startswith(f"{created.client_id}\tmachine\t")
    assert f"resource={PROMPTLAB} scope=exam.read smoke.submit" in row
    assert lines["client_secret"] not in row


def test_rotate_secret_handles_machine_clients(client: Client, machine: IssuedClient) -> None:
    out = io.StringIO()
    call_command("clients", "rotate-secret", "--client-id", machine.client.client_id, stdout=out)
    secret = next(
        line.split(": ", 1)[1]
        for line in out.getvalue().splitlines()
        if line.startswith("client_secret: ")
    )

    old = post_token(client, credentials_form(), basic(machine.client.client_id, machine.secret))
    new = post_token(client, credentials_form(), basic(machine.client.client_id, secret))
    assert old.status_code == 401
    assert new.status_code == 200


@pytest.mark.parametrize(
    ("resource", "scopes", "error"),
    [
        ("https://nowhere.example/api", ["smoke.submit"], UnknownResource),
        (PROMPTLAB, ["nope"], UnknownScope),
        (PROMPTLAB, [], UnknownScope),
    ],
)
def test_create_machine_refuses_unknown_resource_or_scope(
    promptlab: Resource, resource: str, scopes: list[str], error: type[Exception]
) -> None:
    with pytest.raises(error):
        create_machine_client("x", resource, scopes, actor="test")
    with pytest.raises(CommandError):
        call_command(
            "clients",
            "create-machine",
            "--name",
            "x",
            "--resource",
            resource,
            "--scope",
            " ".join(scopes),
        )
    assert not OAuthClient.objects.filter(kind=OAuthClient.Kind.MACHINE).exists()


def test_token_lifetime_is_the_access_token_lifetime(
    client: Client, machine: IssuedClient, frozen_clock: FrozenClock
) -> None:
    token = post_token(
        client, credentials_form(), basic(machine.client.client_id, machine.secret)
    ).json()["access_token"]
    jwks = JwksCache(jwks_fetcher(client), frozen_clock)
    frozen_clock.advance(int(timedelta(minutes=11).total_seconds()))

    with pytest.raises(TokenRejected):
        validate_machine_access_token(
            token,
            jwks=jwks,
            audience=PROMPTLAB,
            machine_client_ids=frozenset({machine.client.client_id}),
            required_scope="smoke.submit",
            clock=frozen_clock,
        )
