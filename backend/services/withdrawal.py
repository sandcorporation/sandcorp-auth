"""Withdrawal of a member (#39, ADR 0004) and the purge of withdrawn accounts.

`withdraw_member` (「내 계정」 → 탈퇴), in one transaction:
- the account becomes inactive (`User.is_active` False, `Member.status` 「탈퇴」, `withdrawn_at`):
  sign-in, `/authorize`, `/token` (code and refresh) and `/userinfo` refuse it, and every
  session of it stops being signed in (Django's ModelBackend drops inactive users);
- every consent is revoked with its refresh token families;
- its social identities are deleted, so the same Google/Kakao account signs up anew (a new
  `sub`, nothing restored, no 「이전 계정」 notice);
- the IP of its audit events is erased;
- `user.deleted` is queued for every client it ever consented to that has a webhook.

`purge_withdrawn` (`manage.py members purge`, daily) erases, PURGE_AFTER after withdrawal, the
email, name, remaining identities, terms agreements and consents; the User and Member rows stay
as the tombstone of the `sub` (never reused), with `withdrawn_at` and `purged_at`. The same run
deletes audit events older than AUDIT_RETENTION, finished webhook deliveries older than
PURGE_AFTER and idle request-limit counters (they hold IPs).
"""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Final

from django.contrib.auth.models import User
from django.db import transaction

from accounts.models import ExternalIdentity, Member, TermsAgreement
from adapters.clock import get_clock
from audit.models import AuditEvent
from oauth.models import Client, Consent, RefreshTokenFamily, WebhookDelivery
from oauth.tokens import revoke_family
from services import audit, throttle
from services.audit import JSON
from services.consents import revoke_consent
from services.webhooks import enqueue_user_deleted

CONFIRM_PHRASE: Final = "탈퇴합니다"
PURGE_AFTER: Final = timedelta(days=30)
AUDIT_RETENTION: Final = timedelta(days=365)
REVOKE_REASON: Final = "member_withdrawn"


def withdraw_member(user: User) -> bool:
    """Withdraw the member `user` (see the module docstring). Returns False when it was already
    withdrawn (nothing is done then). Callers pass members only."""
    now = get_clock().now()
    sub = user.get_username()
    with transaction.atomic():
        claimed = (
            Member.objects.filter(user_id=user.pk)
            .exclude(status=Member.Status.WITHDRAWN)
            .update(status=Member.Status.WITHDRAWN, withdrawn_at=now)
        )
        if not claimed:
            return False
        User.objects.filter(pk=user.pk).update(is_active=False)
        user.is_active = False
        # Before revoking: every client the member ever consented to hears of it.
        clients = list(Client.objects.filter(consents__user=user).distinct().order_by("pk"))
        for consent in Consent.objects.filter(user=user, revoked_at__isnull=True).select_related(
            "client", "resource"
        ):
            revoke_consent(consent, reason=REVOKE_REASON, actor=sub, ip="")
        for family in RefreshTokenFamily.objects.filter(user=user, revoked_at__isnull=True):
            revoke_family(family, REVOKE_REASON)
        identities: list[JSON] = [
            str(provider)
            for provider in sorted(
                ExternalIdentity.objects.filter(user=user).values_list("provider", flat=True)
            )
        ]
        ExternalIdentity.objects.filter(user=user).delete()
        AuditEvent.objects.filter(actor=sub).exclude(ip="").update(ip="")
        queued = enqueue_user_deleted(sub, now, clients)
        audit.record(
            audit.MEMBER_WITHDRAWN,
            actor=sub,
            detail={"identities": identities, "webhooks": queued},
        )
    return True


@dataclass
class PurgeReport:
    members: list[str] = field(default_factory=list)
    audit_events: int = 0
    webhook_deliveries: int = 0
    throttle_counters: int = 0


def purge_withdrawn(*, dry_run: bool = False) -> PurgeReport:
    """Erase what PURGE_AFTER has run out for (see the module docstring). With `dry_run`,
    count only."""
    now = get_clock().now()
    due = Member.objects.filter(
        status=Member.Status.WITHDRAWN,
        withdrawn_at__lte=now - PURGE_AFTER,
        purged_at__isnull=True,
    ).select_related("user")
    old_events = AuditEvent.objects.filter(at__lt=now - AUDIT_RETENTION)
    finished = WebhookDelivery.objects.filter(created_at__lte=now - PURGE_AFTER).exclude(
        delivered_at__isnull=True, gave_up_at__isnull=True
    )
    report = PurgeReport(members=[member.user.get_username() for member in due])
    if dry_run:
        report.audit_events = old_events.count()
        report.webhook_deliveries = finished.count()
        return report
    for member in due:
        _purge_member(member)
    report.audit_events, _ = old_events.delete()
    report.webhook_deliveries, _ = finished.delete()
    report.throttle_counters = throttle.purge_stale()
    return report


def _purge_member(member: Member) -> None:
    user = member.user
    now = get_clock().now()
    with transaction.atomic():
        claimed = Member.objects.filter(pk=member.pk, purged_at__isnull=True).update(
            purged_at=now, email_verified=False
        )
        if not claimed:
            return
        User.objects.filter(pk=user.pk).update(email="", first_name="", last_name="")
        ExternalIdentity.objects.filter(user=user).delete()
        TermsAgreement.objects.filter(user=user).delete()
        # Consents cascade to their codes, refresh token families and tokens.
        Consent.objects.filter(user=user).delete()
        audit.record(audit.MEMBER_PURGED, actor=user.get_username())
