"""Machine clients (#76): programs that get tokens for themselves, with no person behind them.

Registered only by the owner (`manage.py clients create-machine`), bound to one resource and a
fixed set of that resource's scopes. At `/token` they use `grant_type=client_credentials` with
`client_secret_basic` or `client_secret_post` and get a short-lived access token whose
`sub` is `client:<client_id>` and `acct` is `"machine"` (docs/resource-server-token-validation.md
12절), never a refresh token. The secret follows the confidential client rules: shown once,
stored as a Django password hash, replaced by `services.confidential_clients.rotate_client_secret`.
"""

from collections.abc import Iterable, Sequence
from typing import Final

from django.contrib.auth.hashers import make_password
from django.db import transaction

from adapters.clock import get_clock
from oauth.models import Client, Resource
from services import audit
from services.confidential_clients import SECRET_BYTES, IssuedClient
from services.signing import random_token

MACHINE: Final = "machine"  # the `acct` claim of a machine token
MACHINE_SUB_PREFIX: Final = "client:"


class MachineClientError(ValueError):
    pass


class UnknownResource(MachineClientError):
    pass


class UnknownScope(MachineClientError):
    pass


class ResourceRefused(MachineClientError):
    """A `resource` other than the client's own was asked for."""


class ScopeRefused(MachineClientError):
    """A scope the client is not bound to was asked for (or none of its scopes is left)."""


def machine_sub(client: Client) -> str:
    return MACHINE_SUB_PREFIX + client.client_id


@transaction.atomic
def create_machine_client(
    name: str, resource_url: str, scopes: Iterable[str], *, actor: str, ip: str = ""
) -> IssuedClient:
    """Register a machine client bound to `resource_url` and `scopes` (names of that
    resource's scopes) and return it with its secret (shown once). Raises MachineClientError."""
    name = name.strip()
    if not name:
        raise MachineClientError("이름이 필요합니다")
    resource = Resource.objects.filter(url=resource_url.strip()).first()
    if resource is None:
        raise UnknownResource(f"등록된 리소스가 아닙니다: {resource_url}")
    names = sorted({scope.strip() for scope in scopes if scope.strip()})
    if not names:
        raise UnknownScope("스코프가 하나 이상 있어야 합니다")
    known = set(resource.scopes.filter(name__in=names).values_list("name", flat=True))
    if missing := [scope for scope in names if scope not in known]:
        raise UnknownScope(f"{resource.url}의 스코프가 아닙니다: {' '.join(missing)}")
    secret = random_token(SECRET_BYTES)
    client = Client.objects.create(
        client_id=random_token(),
        name=name[:200],
        redirect_uris=[],
        kind=Client.Kind.MACHINE,
        secret_hash=make_password(secret),
        registered_via=Client.Via.ADMIN,
        created_at=get_clock().now(),
        machine_resource=resource,
        machine_scopes=names,
    )
    audit.record(
        audit.CLIENT_CREATED,
        actor=actor,
        client_id=client.client_id,
        ip=ip,
        detail={
            "client_id": client.client_id,
            "name": client.name,
            "kind": MACHINE,
            "resource": resource.url,
            "scope": " ".join(names),
        },
    )
    return IssuedClient(client, secret)


def machine_grant(
    client: Client, requested_resources: Sequence[str], requested_scope: str | None
) -> tuple[Resource, list[str]]:
    """What a client_credentials request of a machine client gets: its own resource (a
    `resource` parameter, if sent, must be exactly that one) and the requested scopes, all of
    which must be bound to it (none requested = all of them). Scopes deleted from the resource
    since the client was made are dropped. Raises ResourceRefused or ScopeRefused."""
    resource = client.machine_resource
    if client.kind != Client.Kind.MACHINE or resource is None:
        raise ResourceRefused("not a machine client")
    if requested_resources and list(requested_resources) != [resource.url]:
        raise ResourceRefused(f"This client may only ask for {resource.url}.")
    bound: list[str] = list(client.machine_scopes)
    asked = sorted(set((requested_scope or "").split())) or sorted(bound)
    if refused := [scope for scope in asked if scope not in bound]:
        raise ScopeRefused(f"Scopes not bound to this client: {refused}")
    live = set(resource.scopes.filter(name__in=asked).values_list("name", flat=True))
    granted = [scope for scope in asked if scope in live]
    if not granted:
        raise ScopeRefused(f"No scope of {resource.url} is left for this client.")
    return resource, granted
