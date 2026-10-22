"""Revoking a consent: the one way a consent dies, wherever it happens (admin, or a wider
consent replacing it on the consent screen).

A revoked consent takes every live refresh token family it opened with it, so nothing it
allowed can be refreshed any more, and the next `/authorize` for that client and resource asks
the owner again.
"""

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
