"""Revoking a consent: the one way a consent dies, wherever it happens (admin, or a wider
consent replacing it on the consent screen).

A revoked consent takes every live refresh token family it opened with it, so nothing it
allowed can be refreshed any more, and the next `/authorize` for that client and resource asks
the owner again.
"""

from dataclasses import dataclass
from datetime import datetime

from django.contrib.auth.models import User
from django.db import transaction

from adapters.clock import get_clock
from oauth.models import Consent, RefreshTokenFamily
from oauth.tokens import revoke_family
from services import audit


def revoke_consent(consent: Consent, *, reason: str, actor: str, ip: str) -> bool:
    """Revoke `consent` (if still live) and its live families with `reason`; record it.
    Returns False when the consent was already revoked (nothing is done then)."""
    now = get_clock().now()
    with transaction.atomic():
        claimed = Consent.objects.filter(pk=consent.pk, revoked_at__isnull=True).update(
            revoked_at=now
        )
        if not claimed:
            return False
        consent.revoked_at = now
        families = list(RefreshTokenFamily.objects.filter(consent=consent, revoked_at__isnull=True))
        for family in families:
            revoke_family(family, reason)
        audit.record(
            audit.CONSENT_REVOKED,
            actor=actor,
            client_id=consent.client.client_id,
            ip=ip,
            detail={
                "resource": consent.resource.url,
                "scope": " ".join(consent.scopes),
                "reason": reason,
                "families": [family.pk for family in families],
            },
        )
    return True


@dataclass(frozen=True)
class ConnectedApp:
    client_id: int
    name: str
    since: datetime
    shares: list[str]


def connected_apps(user: User) -> list[ConnectedApp]:
    """The apps `user` has a live consent for, one row per client (a client may hold consents
    for several resources), oldest first. `shares` is what the app sees, in plain words."""
    apps: dict[int, ConnectedApp] = {}
    for consent in (
        Consent.objects.filter(user=user, revoked_at__isnull=True)
        .select_related("client")
        .order_by("granted_at", "pk")
    ):
        scopes = set(consent.scopes)
        shares = [
            label for scope, label in (("email", "이메일"), ("profile", "이름")) if scope in scopes
        ]
        known = apps.get(consent.client_id)
        if known is None:
            apps[consent.client_id] = ConnectedApp(
                consent.client_id, consent.client.name, consent.granted_at, shares
            )
        else:
            known.shares.extend(label for label in shares if label not in known.shares)
    return list(apps.values())


def disconnect_app(user: User, client_pk: int, *, ip: str) -> bool:
    """「연결 끊기」: revoke every live consent `user` gave the client, refresh token families
    with them. Returns False when there was none (already disconnected)."""
    consents = list(
        Consent.objects.filter(
            user=user, client_id=client_pk, revoked_at__isnull=True
        ).select_related("client")
    )
    for consent in consents:
        revoke_consent(consent, reason="user_disconnected", actor=user.get_username(), ip=ip)
    return bool(consents)
