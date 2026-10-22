"""Confidential clients: the sites' admin screens log in with `client_secret_basic`.

They are registered only by the owner (management command `clients` or the admin add form),
never by DCR/CIMD. The secret is shown once when it is issued; only its Django password hash
is stored, so a lost secret is replaced (`rotate_client_secret`), never recovered.
"""

from collections.abc import Iterable
from typing import NamedTuple
from urllib.parse import urlsplit

from django.contrib.auth.hashers import make_password
from django.db import transaction

from adapters.clock import get_clock
from oauth.models import Client
from services import audit
from services.redirect_uris import valid_redirect_uri
from services.signing import random_token

SECRET_BYTES = 32


class IssuedClient(NamedTuple):
    client: Client
    secret: str  # the raw secret: show it once, never store it


class InvalidRedirectUri(ValueError):
    pass


class NotConfidential(ValueError):
    pass


def confidential_redirect_uris(uris: Iterable[str]) -> list[str]:
    """The URIs as given (order kept, duplicates dropped), each https with a host and no
    fragment: the loopback http exception is for public clients only. Matching is exact, so
    a trailing slash is part of the value. Raises InvalidRedirectUri."""
    checked: list[str] = []
    for uri in uris:
        uri = uri.strip()
        if not uri or uri in checked:
            continue
        if not valid_redirect_uri(uri) or urlsplit(uri).scheme != "https":
            raise InvalidRedirectUri(f"리다이렉트 URI는 https여야 합니다: {uri}")
        checked.append(uri)
    if not checked:
        raise InvalidRedirectUri("리다이렉트 URI가 하나 이상 있어야 합니다")
    return checked


@transaction.atomic
def create_confidential_client(
    name: str, redirect_uris: Iterable[str], *, actor: str, ip: str = ""
) -> IssuedClient:
    """Register a confidential client and return it with its secret (shown once)."""
    name = name.strip()
    if not name:
        raise ValueError("이름이 필요합니다")
    uris = confidential_redirect_uris(redirect_uris)
    secret = random_token(SECRET_BYTES)
    client = Client.objects.create(
        client_id=random_token(),
        name=name[:200],
        redirect_uris=uris,
        kind=Client.Kind.CONFIDENTIAL,
        secret_hash=make_password(secret),
        registered_via=Client.Via.ADMIN,
        created_at=get_clock().now(),
    )
    audit.record(
        audit.CLIENT_CREATED,
        actor=actor,
        client_id=client.client_id,
        ip=ip,
        detail={"client_id": client.client_id, "name": client.name},
    )
    return IssuedClient(client, secret)


@transaction.atomic
def rotate_client_secret(client: Client, *, actor: str, ip: str = "") -> str:
    """Issue a new secret for a confidential client; the old one stops working at once."""
    if client.kind != Client.Kind.CONFIDENTIAL:
        raise NotConfidential(f"기밀 클라이언트가 아닙니다: {client.client_id}")
    secret = random_token(SECRET_BYTES)
    client.secret_hash = make_password(secret)
    client.save(update_fields=["secret_hash"])
    audit.record(
        audit.CLIENT_SECRET_ROTATED,
        actor=actor,
        client_id=client.client_id,
        ip=ip,
        detail={"client_id": client.client_id, "name": client.name},
    )
    return secret
