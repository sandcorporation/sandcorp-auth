"""Sandcorp members (ADR 0003): accounts next to the owner, made from a social login.

A member is a Django User with a `accounts.Member` row: `username` is its `sub`, an opaque
`m_` + 26-character ULID (Crockford base32) that never changes and is never made from a name or
an email. It has no usable password and is never staff. Its tokens carry the account kind claim
`acct=member` (the owner's tokens carry none, so they stay exactly as before), and it may hold
only `MEMBER_SCOPES`: login, never a resource's `admin` or `editor`. Only a client marked
`allows_members` may get a code or a token for a member.
"""

import re
from dataclasses import dataclass
from typing import Final, Literal

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models.functions import Lower

from accounts.models import ExternalIdentity, Member
from adapters.clock import get_clock
from adapters.randomness import get_randomness
from oauth.models import Client
from services import audit
from services.oidc import LOGIN_INFO_SCOPES
from services.terms import needs_terms

type AccountKind = Literal["owner", "member"]

ACCOUNT_KIND_CLAIM: Final = "acct"
MEMBER: Final = "member"
MEMBER_SUB_PREFIX: Final = "m_"
MEMBER_SUB_PATTERN: Final = r"m_[0-7][0-9A-HJKMNP-TV-Z]{25}"
# Resource scopes a member may hold (besides the login info scopes): sign-in only.
MEMBER_RESOURCE_SCOPES: Final = frozenset({"login"})
MEMBER_SCOPES: Final = MEMBER_RESOURCE_SCOPES | LOGIN_INFO_SCOPES

_CROCKFORD: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MEMBER_SUB = re.compile(MEMBER_SUB_PATTERN)


class IdentityTaken(Exception):
    """This (provider, provider sub) already belongs to an account."""


class MemberClientRefused(Exception):
    """The client does not allow members."""


class MemberTermsPending(Exception):
    """The member has not agreed to the current terms (or is still 「동의 대기」, #37)."""


class MemberScopeRefused(Exception):
    """A member asked for scopes only the owner may hold."""

    def __init__(self, scopes: list[str]) -> None:
        super().__init__(" ".join(scopes))
        self.scopes = scopes


@dataclass(frozen=True)
class ExternalProfile:
    """What a provider says about the person at sign-in (#36 fills it from Google/Kakao)."""

    provider: str
    provider_sub: str
    email: str = ""
    email_verified: bool = False
    display_name: str = ""


def new_member_sub() -> str:
    """`m_` + a ULID: 48-bit milliseconds of `get_clock()` and 80 random bits, base32."""
    millis = int(get_clock().now().timestamp() * 1000) & ((1 << 48) - 1)
    value = (millis << 80) | int.from_bytes(get_randomness().token_bytes(10), "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return MEMBER_SUB_PREFIX + "".join(reversed(chars))


def is_member_sub(username: str) -> bool:
    return _MEMBER_SUB.fullmatch(username) is not None


def create_member(profile: ExternalProfile) -> User:
    """A new member account with `profile` as its first identity. Raises IdentityTaken if the
    identity is already linked (to anyone), ValueError for an unknown provider."""
    if profile.provider not in ExternalIdentity.Provider.values:
        raise ValueError(f"unknown provider: {profile.provider!r}")
    now = get_clock().now()
    email = profile.email.strip()
    try:
        with transaction.atomic():
            user = User(
                username=new_member_sub(),
                email=email,
                first_name=profile.display_name.strip()[:150],
                date_joined=now,
            )
            user.set_unusable_password()
            user.save()
            Member.objects.create(
                user=user, created_at=now, email_verified=bool(email) and profile.email_verified
            )
            ExternalIdentity.objects.create(
                user=user,
                provider=profile.provider,
                provider_sub=profile.provider_sub,
                email=email,
                email_verified=profile.email_verified,
                display_name=profile.display_name.strip()[:150],
                linked_at=now,
            )
    except IntegrityError as error:
        if ExternalIdentity.objects.filter(
            provider=profile.provider, provider_sub=profile.provider_sub
        ).exists():
            raise IdentityTaken(f"{profile.provider} identity is already linked") from error
        raise
    return user


def is_member(user: User) -> bool:
    return Member.objects.filter(user_id=user.pk).exists()


def account_kind(user: User) -> AccountKind:
    """`member` for a member, `owner` for the owner (the superuser without a Member row)."""
    if is_member(user):
        return "member"
    if user.is_superuser:
        return "owner"
    raise RuntimeError(f"account {user.pk} is neither the owner nor a member")


def member_email_verified(user: User) -> bool:
    member = Member.objects.filter(user_id=user.pk).first()
    return member is not None and member.email_verified


def check_member_grant(user: User, client: Client, scopes: list[str]) -> None:
    """For a member: the client must allow members and every scope must be a member scope.
    and it must have agreed to the current terms (#37). Raises MemberClientRefused /
    MemberScopeRefused / MemberTermsPending, in that order; does nothing for the owner."""
    if not is_member(user):
        return
    if not client.allows_members:
        raise MemberClientRefused(client.client_id)
    refused = sorted(set(scopes) - MEMBER_SCOPES)
    if refused:
        raise MemberScopeRefused(refused)
    if needs_terms(user):
        raise MemberTermsPending(user.username)


def set_allows_members(client: Client, allowed: bool, *, actor: str, ip: str = "") -> None:
    """Turn the client's "allows members" mark on or off, with an audit record."""
    Client.objects.filter(pk=client.pk).update(allows_members=allowed)
    client.allows_members = allowed
    record_members_changed(client, actor=actor, ip=ip)


def record_members_changed(client: Client, *, actor: str, ip: str = "") -> None:
    audit.record(
        audit.CLIENT_MEMBERS_CHANGED,
        actor=actor,
        client_id=client.client_id,
        ip=ip,
        detail={"client_id": client.client_id, "allows_members": client.allows_members},
    )


EMAIL_MAX_LENGTH: Final = 254  # django.contrib.auth User.email


class InvalidEmail(Exception):
    pass


class EmailTaken(Exception):
    pass


def set_member_email(user: User, email: str, *, ip: str = "") -> None:
    """The member types (or changes) their account email on 「내 계정」: it is theirs, not the
    provider's word, so it is kept unverified. Raises InvalidEmail, EmailTaken (another member
    has it). Callers pass members only."""
    cleaned = email.strip()
    try:
        validate_email(cleaned)
    except ValidationError as error:
        raise InvalidEmail(cleaned) from error
    if len(cleaned) > EMAIL_MAX_LENGTH:
        raise InvalidEmail(cleaned)
    with transaction.atomic():
        User.objects.select_for_update().filter(pk=user.pk).first()
        taken = (
            User.objects.alias(e=Lower("email"))
            .filter(e=cleaned.lower(), member__isnull=False)
            .exclude(pk=user.pk)
            .exists()
        )
        if taken:
            raise EmailTaken(cleaned)
        user.email = cleaned
        user.save(update_fields=["email"])
        Member.objects.filter(user_id=user.pk).update(email_verified=False)
    audit.record(audit.MEMBER_EMAIL_CHANGED, actor=user.get_username(), ip=ip)
