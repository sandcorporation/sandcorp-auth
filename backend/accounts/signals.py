"""One owner only: refuse a second non-member User from any path (createsuperuser, admin,
shell), not only from `manage.py owner create`. Members (ADR 0003) are made by
`services.members.create_member` with an `m_` ULID username and are never staff.

Also: a login or logout drops the messages queued before it (#152)."""

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.http import HttpRequest

from accounts.session import drop_messages
from services.members import is_member_sub
from services.owner import OwnerExists


@receiver(pre_save, sender=User)
def refuse_second_account(sender: type[User], instance: User, **kwargs: object) -> None:
    if not instance._state.adding:
        return
    if is_member_sub(instance.username):
        if instance.is_staff or instance.is_superuser:
            raise ValueError("a member account is never staff")
        return
    if User.objects.exclude(pk=instance.pk).filter(member__isnull=True).exists():
        raise OwnerExists("the owner account already exists; only one owner is allowed")


@receiver(user_logged_in)
@receiver(user_logged_out)
def drop_unread_messages(sender: object, request: HttpRequest | None, **kwargs: object) -> None:
    """Messages unread at a logout (or left by a session that ran out) never reach the next
    account in the same browser (#152): 「내 계정」 saves name the email address."""
    if request is not None:
        drop_messages(request)
