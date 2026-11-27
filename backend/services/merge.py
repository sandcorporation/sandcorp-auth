"""Merging a member into the owner (#100, `manage.py members merge`).

The owner signed up once more as a member with a social login. Merging moves what that member
account holds to the owner and removes it, without anyone losing data downstream:

- its social logins (`ExternalIdentity`) move to the owner; if the owner already has a login of
  the same provider, nothing is done (`MergeRefused`);
- its live consents move to the owner (one the owner already has for the same client and
  resource gets the member's scopes added);
- its refresh token families are revoked and its sessions deleted;
- the clients it ever consented to that have a webhook get `user.merged {from_sub, to_sub}`
  (never `user.deleted`: the sites move the data instead of deleting it);
- the member account is deleted. Its terms agreements go with it: the person keeps using the
  service as the owner, who has no terms to agree to. What it agreed to (versions and times)
  stays in the `member.merged` audit record, kept as long as any audit record (ADR 0004).
"""

from dataclasses import dataclass, field

from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.db import transaction

from accounts.models import ExternalIdentity, Member, TermsAgreement
from adapters.clock import get_clock
from oauth.models import Client, Consent, RefreshTokenFamily
from oauth.tokens import revoke_family
from services import audit
from services.locks import lock_account
from services.members import is_member
from services.webhooks import enqueue_user_merged

REVOKE_REASON = "account_merged"


class MergeRefused(Exception):
    """Nothing was changed; the message says why."""


@dataclass(frozen=True)
class MergeReport:
    from_sub: str
    to_sub: str
    identities: list[str] = field(default_factory=list)
    consents_moved: int = 0
    consents_combined: int = 0
    families_revoked: int = 0
    sessions_deleted: int = 0
    terms_agreements: int = 0
    webhooks: int = 0


def _accounts(from_username: str, into_username: str) -> tuple[User, User]:
    if from_username == into_username:
        raise MergeRefused("--from and --into are the same account")
    source = User.objects.filter(username=from_username).first()
    if source is None or not is_member(source):
        raise MergeRefused(f"{from_username}: no such member")
    member = Member.objects.get(user=source)
    if member.status == Member.Status.WITHDRAWN or not source.is_active:
        raise MergeRefused(f"{from_username}: the member has withdrawn")
    target = User.objects.filter(username=into_username).first()
    if target is None or is_member(target) or not target.is_superuser or not target.is_active:
        raise MergeRefused(f"{into_username}: not the owner")
    return source, target


def _session_keys(user: User) -> list[str]:
    now = get_clock().now()
    wanted = str(user.pk)
    return [
        session.session_key
        for session in Session.objects.filter(expire_date__gt=now)
        if str(session.get_decoded().get("_auth_user_id")) == wanted
    ]


def merge_member_into_owner(
    from_username: str, into_username: str, *, dry_run: bool = False
) -> MergeReport:
    """Merge the member `from_username` into the owner `into_username` (see the module
    docstring). With `dry_run`, only count. Raises MergeRefused; then nothing is changed."""
    with transaction.atomic():
        source, target = _accounts(from_username, into_username)
        # Lock both accounts first (services.locks): a link, a login, a refresh or a second
        # merge waits for this one.
        lock_account(source.pk, target.pk)
        identities = list(ExternalIdentity.objects.filter(user=source).order_by("pk"))
        providers = sorted({identity.provider for identity in identities})
        taken = set(
            ExternalIdentity.objects.filter(user=target, provider__in=providers).values_list(
                "provider", flat=True
            )
        )
        if taken:
            raise MergeRefused(f"{into_username} already has a login of {', '.join(sorted(taken))}")
        consents = list(Consent.objects.filter(user=source, revoked_at__isnull=True).order_by("pk"))
        existing = {
            (c.client_id, c.resource_id): c
            for c in Consent.objects.filter(user=target, revoked_at__isnull=True)
        }
        families = list(RefreshTokenFamily.objects.filter(user=source, revoked_at__isnull=True))
        sessions = _session_keys(source)
        agreements = list(
            TermsAgreement.objects.filter(user=source).select_related("document").order_by("pk")
        )
        clients = list(Client.objects.filter(consents__user=source).distinct().order_by("pk"))
        hooked = [c for c in clients if c.webhook_url and c.webhook_secret_encrypted is not None]
        combined = [c for c in consents if (c.client_id, c.resource_id) in existing]
        report = MergeReport(
            from_sub=source.username,
            to_sub=target.username,
            identities=providers,
            consents_moved=len(consents) - len(combined),
            consents_combined=len(combined),
            families_revoked=len(families),
            sessions_deleted=len(sessions),
            terms_agreements=len(agreements),
            webhooks=len(hooked),
        )
        if dry_run:
            return report

        for family in families:
            revoke_family(family, REVOKE_REASON)
        for consent in consents:
            kept = existing.get((consent.client_id, consent.resource_id))
            if kept is None:
                Consent.objects.filter(pk=consent.pk).update(user=target)
            else:
                scopes = sorted(set(kept.scopes) | set(consent.scopes))
                Consent.objects.filter(pk=kept.pk).update(scopes=scopes)
        ExternalIdentity.objects.filter(user=source).update(user=target)
        queued = enqueue_user_merged(source.username, target.username, clients)
        audit.record(
            audit.MEMBER_MERGED,
            actor=target.username,
            detail={
                "from_sub": source.username,
                "to_sub": target.username,
                "identities": list(providers),
                "consents_moved": report.consents_moved,
                "consents_combined": report.consents_combined,
                "families_revoked": report.families_revoked,
                "webhooks": queued,
                "terms_agreed": [
                    {
                        "kind": str(a.document.kind),
                        "version": a.document.version,
                        "agreed_at": a.agreed_at.isoformat(),
                    }
                    for a in agreements
                ],
            },
        )
        Session.objects.filter(session_key__in=sessions).delete()
        source.delete()  # Member, terms agreements, revoked consents, codes, families
    return report
