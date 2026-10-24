"""Terms agreement (#37): which document versions are current, whether a member still has to
agree, recording an agreement (with the age-14 confirmation) and registering a new version.

A member may get codes and tokens only when it is 「활성」 and has agreed to the current version
of every kind (`needs_terms` is False); `services.members.check_member_grant` asks this at the
three token gates. The owner is never asked. With no document of some kind registered nobody
can agree, so no member can sign up: a first version must be registered before members come
(`manage.py terms add`, `docs/operations.md`).
"""

from collections.abc import Collection
from datetime import date

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.db.models import Case, QuerySet, Value, When
from django.utils import timezone

from accounts.models import Member, TermsAgreement, TermsDocument
from adapters.clock import get_clock
from services import audit


class TermsError(Exception):
    """An agreement or a registration that cannot be taken."""


class TermsUnavailable(TermsError):
    """Some kind of document has no version in effect: nobody can agree yet."""


class AgeNotConfirmed(TermsError):
    """The age-14 confirmation was not given."""


class TermsNotAccepted(TermsError):
    """The agreement does not name exactly the current version of every document."""


class TermsVersionExists(TermsError):
    """This kind already has a version with that name."""


def current_documents() -> QuerySet[TermsDocument]:
    """The version in effect of each kind (latest effective date up to today, then the latest
    registered), 이용약관 first. A kind with no version in effect is missing."""
    today = timezone.localdate(get_clock().now())
    ids = []
    for kind in TermsDocument.Kind:
        current = (
            TermsDocument.objects.filter(kind=kind, effective_date__lte=today)
            .order_by("-effective_date", "-id")
            .values_list("id", flat=True)
            .first()
        )
        if current is not None:
            ids.append(current)
    order = Case(
        *(When(kind=kind, then=Value(i)) for i, kind in enumerate(TermsDocument.Kind)),
        default=Value(len(TermsDocument.Kind)),
    )
    return TermsDocument.objects.filter(id__in=ids).order_by(order)


def needs_terms(user: User) -> bool:
    """True for a member that may not get tokens yet: still 「동의 대기」, or the current version
    of some document is not agreed to (or there is none). Always False for the owner."""
    status = Member.objects.filter(user_id=user.pk).values_list("status", flat=True).first()
    if status is None:
        return False
    if status != Member.Status.ACTIVE:
        return True
    current = list(current_documents().values_list("id", flat=True))
    if len(current) < len(TermsDocument.Kind):
        return True
    agreed = TermsAgreement.objects.filter(user_id=user.pk, document_id__in=current).count()
    return agreed < len(current)


def agree_to_terms(
    user: User, *, document_ids: Collection[int], age_confirmed: bool, ip: str = ""
) -> None:
    """Record the member's agreement to the current versions and make it 「활성」. The ids must
    be exactly the current versions (a version that took effect after the screen was shown is
    refused, so the member sees it). Raises a TermsError; records nothing then."""
    current = list(current_documents())
    if len(current) < len(TermsDocument.Kind):
        raise TermsUnavailable()
    if not age_confirmed:
        raise AgeNotConfirmed()
    if set(document_ids) != {document.pk for document in current}:
        raise TermsNotAccepted()
    now = get_clock().now()
    with transaction.atomic():
        member = Member.objects.select_for_update().get(user_id=user.pk)
        already = set(
            TermsAgreement.objects.filter(user_id=user.pk).values_list("document_id", flat=True)
        )
        TermsAgreement.objects.bulk_create(
            TermsAgreement(user=user, document=document, agreed_at=now, age_confirmed=True)
            for document in current
            if document.pk not in already
        )
        if member.status != Member.Status.ACTIVE:
            member.status = Member.Status.ACTIVE
            member.save(update_fields=["status"])
        audit.record(
            audit.TERMS_AGREED,
            actor=user.username,
            ip=ip,
            detail={"versions": {d.kind: d.version for d in current}, "age_confirmed": True},
        )


def register_document(
    *, kind: str, version: str, effective_date: date, url: str, actor: str, ip: str = ""
) -> TermsDocument:
    """A new version of a document, with an audit record. Raises TermsVersionExists."""
    try:
        with transaction.atomic():
            document = TermsDocument.objects.create(
                kind=kind,
                version=version,
                effective_date=effective_date,
                url=url,
                created_at=get_clock().now(),
            )
    except IntegrityError:
        raise TermsVersionExists(f"{kind} {version}") from None
    record_registered(document, actor=actor, ip=ip)
    return document


def record_registered(document: TermsDocument, *, actor: str, ip: str = "") -> None:
    audit.record(
        audit.TERMS_REGISTERED,
        actor=actor,
        ip=ip,
        detail={
            "kind": document.kind,
            "version": document.version,
            "effective_date": document.effective_date.isoformat(),
            "url": document.url,
        },
    )
