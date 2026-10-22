"""The owner account: the single Django User. Created and reset by `manage.py owner`."""

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.db import transaction

from accounts.models import TotpDevice


class OwnerExists(Exception):
    """A second account was refused: there is only ever one owner."""


class NoOwner(Exception):
    """No owner account yet: run `manage.py owner create`."""


def get_owner() -> User:
    owner = User.objects.order_by("pk").first()
    if owner is None:
        raise NoOwner("no owner account; run `manage.py owner create`")
    return owner


def create_owner(username: str, password: str) -> User:
    """Create the owner (staff + superuser, TOTP not enrolled). Raises OwnerExists, or
    django ValidationError for a weak password."""
    validate_password(password)
    with transaction.atomic():
        if User.objects.select_for_update().exists():
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
