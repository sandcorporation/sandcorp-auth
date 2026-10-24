"""One owner only: refuse a second non-member User from any path (createsuperuser, admin,
shell), not only from `manage.py owner create`. Members (ADR 0003) are made by
`services.members.create_member` with an `m_` ULID username and are never staff."""

from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver

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
