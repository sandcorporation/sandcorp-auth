"""Public clients the owner registers (#102, ADR 0007): a program installed on one PC that
listens on loopback and logs in with PKCE and no client secret (RFC 8252).

Registered only by the owner (`manage.py clients create-public`), never by DCR/CIMD. With
`login_info=True` the client may ask for openid/profile/email (`oauth.grants.requested_scopes`);
then its redirect URIs are exact loopback IP URIs (`exact_loopback_redirect_uri`) and every
/authorize shows the consent screen (`oauth.views.authorize`).
"""

from collections.abc import Iterable

from django.db import transaction

from adapters.clock import get_clock
from oauth.models import Client
from services import audit
from services.confidential_clients import InvalidRedirectUri
from services.redirect_uris import exact_loopback_redirect_uri
from services.signing import new_client_id


def public_redirect_uris(uris: Iterable[str]) -> list[str]:
    """The URIs as given (order kept, duplicates dropped), each
    `http://127.0.0.1:<port>/…` or `http://[::1]:<port>/…`. Raises InvalidRedirectUri."""
    checked: list[str] = []
    for uri in uris:
        uri = uri.strip()
        if not uri or uri in checked:
            continue
        if not exact_loopback_redirect_uri(uri):
            raise InvalidRedirectUri(
                "리다이렉트 URI는 포트가 있는 http://127.0.0.1:<포트>/… 또는 "
                f"http://[::1]:<포트>/… 여야 합니다: {uri}"
            )
        checked.append(uri)
    if not checked:
        raise InvalidRedirectUri("리다이렉트 URI가 하나 이상 있어야 합니다")
    return checked


@transaction.atomic
def create_public_client(
    name: str,
    redirect_uris: Iterable[str],
    *,
    login_info: bool,
    actor: str,
    ip: str = "",
) -> Client:
    """Register a public loopback client. Raises InvalidRedirectUri or ValueError (no name)."""
    name = name.strip()
    if not name:
        raise ValueError("이름이 필요합니다")
    uris = public_redirect_uris(redirect_uris)
    client = Client.objects.create(
        client_id=new_client_id(),
        name=name[:200],
        redirect_uris=uris,
        kind=Client.Kind.PUBLIC,
        registered_via=Client.Via.ADMIN,
        allows_login_info=login_info,
        created_at=get_clock().now(),
    )
    audit.record(
        audit.CLIENT_CREATED,
        actor=actor,
        client_id=client.client_id,
        ip=ip,
        detail={
            "client_id": client.client_id,
            "name": client.name,
            "kind": client.kind,
            "login_info": login_info,
        },
    )
    return client
