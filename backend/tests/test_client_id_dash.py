"""`client_id`s and the `--client-id` option of `manage.py clients` (#155).

`client_id` is urlsafe base64, so a raw draw can start with `-`; argparse then reads
`--client-id <id>` as an option. New ids are drawn again; existing ones go as `--client-id=<id>`.
"""

import io
import re
from collections.abc import Iterator

import pytest
from django.contrib.auth.hashers import make_password
from django.core.management import CommandError, call_command
from django.utils import timezone

from adapters.randomness import set_randomness
from oauth.models import Client as OAuthClient
from services.signing import b64url, new_client_id
from tests.conftest import RecordingRandomness

DASH_BYTES = b"\xf8" * 16  # b64url starts with "-"


class DashFirst(RecordingRandomness):
    """Hands out a `-`-leading 16-byte draw first, then the usual deterministic bytes."""

    def __init__(self) -> None:
        super().__init__()
        self.dash_pending = True

    def token_bytes(self, n: int) -> bytes:
        if n == len(DASH_BYTES) and self.dash_pending:
            self.dash_pending = False
            self.issued.append(DASH_BYTES)
            return DASH_BYTES
        return super().token_bytes(n)


@pytest.fixture
def dash_first() -> Iterator[DashFirst]:
    randomness = DashFirst()
    previous = set_randomness(randomness)
    yield randomness
    set_randomness(previous)


def test_dash_bytes_would_make_a_dash_id() -> None:
    assert b64url(DASH_BYTES).startswith("-")


def test_new_client_id_draws_again_past_a_leading_dash(dash_first: DashFirst) -> None:
    client_id = new_client_id()
    assert not client_id.startswith("-")
    assert len(client_id) == len(b64url(DASH_BYTES))
    assert re.fullmatch(r"[A-Za-z0-9_-]+", client_id)
    assert DASH_BYTES in dash_first.issued


@pytest.mark.django_db
def test_created_client_takes_the_spaced_option(dash_first: DashFirst) -> None:
    out = io.StringIO()
    call_command(
        "clients",
        "create-confidential",
        "--name",
        "사이트",
        "--redirect-uri",
        "https://site.example/cb",
        stdout=out,
    )
    found = re.search(r"client_id: (\S+)", out.getvalue())
    assert found is not None
    client_id = found.group(1)
    assert not client_id.startswith("-")

    call_command("clients", "rotate-secret", "--client-id", client_id, stdout=io.StringIO())


@pytest.fixture
def dash_client(db: None) -> OAuthClient:
    """A client made before #155 whose id starts with `-`."""
    return OAuthClient.objects.create(
        client_id="-" + b64url(DASH_BYTES)[1:],
        name="옛 사이트",
        redirect_uris=["https://old.example/cb"],
        kind=OAuthClient.Kind.CONFIDENTIAL,
        secret_hash=make_password("old-secret"),
        registered_via=OAuthClient.Via.ADMIN,
        created_at=timezone.now(),
    )


def test_existing_dash_id_works_with_equals_form(dash_client: OAuthClient) -> None:
    call_command(
        "clients",
        "members",
        f"--client-id={dash_client.client_id}",
        "--allow",
        stdout=io.StringIO(),
    )
    dash_client.refresh_from_db()
    assert dash_client.allows_members


def test_spaced_dash_id_error_points_to_equals_form(dash_client: OAuthClient) -> None:
    with pytest.raises(CommandError, match=r"--client-id=<id>"):
        call_command("clients", "members", "--client-id", dash_client.client_id, "--allow")
