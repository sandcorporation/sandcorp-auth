"""The owner account: the one Django User without a `Member` row (members are ADR 0003).
Created and reset by `manage.py owner`."""

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.db import transaction

from accounts.models import TotpDevice
from services.members import MEMBER_SUB_PREFIX


class OwnerExists(Exception):
    """A second account was refused: there is only ever one owner."""


class NoOwner(Exception):
    """No owner account yet: run `manage.py owner create`."""


def get_owner() -> User:
    owner = User.objects.filter(member__isnull=True).order_by("pk").first()
    if owner is None:
        raise NoOwner("no owner account; run `manage.py owner create`")
    return owner


def create_owner(username: str, password: str) -> User:
    """Create the owner (staff + superuser, TOTP not enrolled). Raises OwnerExists, ValueError
    for a username shaped like a member `sub`, or django ValidationError for a weak password."""
    if username.startswith(MEMBER_SUB_PREFIX):
        raise ValueError(f"the owner's username may not start with {MEMBER_SUB_PREFIX!r}")
    validate_password(password)
    with transaction.atomic():
        if User.objects.select_for_update().filter(member__isnull=True).exists():
            raise OwnerExists("the owner account already exists")
        return User.objects.create_user(
            username, password=password, is_staff=True, is_superuser=True
        )


def set_owner_password(password: str) -> User:
    """Changing the password also ends existing sessions (Django's session auth hash)."""
    owner = get_owner()
    validate_password(password, owner)
    owner.set_password(password)
    owner.save(update_fields=["password"])
    return owner


def reset_owner_totp() -> User:
    """Delete the TOTP device: the next login must enroll again, open sessions end."""
    owner = get_owner()
    TotpDevice.objects.filter(user=owner).delete()
    return owner


def set_owner_email(email: str) -> User:
    """The email OpenID Connect hands out (`email`, `email_verified`). Empty clears it.
    Raises django ValidationError for a malformed address."""
    owner = get_owner()
    email = email.strip()
    if email:
        validate_email(email)
    owner.email = email
    owner.save(update_fields=["email"])
    return owner


def set_owner_name(name: str) -> User:
    """The display name OpenID Connect hands out (`name`), kept whole in `first_name`.
    Empty clears it."""
    owner = get_owner()
    owner.first_name = name.strip()[:150]
    owner.last_name = ""
    owner.save(update_fields=["first_name", "last_name"])
    return owner
