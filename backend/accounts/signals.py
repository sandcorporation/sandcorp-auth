"""Only one account may ever exist: refuse a second User from any path (createsuperuser, admin,
shell), not only from `manage.py owner create`."""

from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver

from services.owner import OwnerExists


@receiver(pre_save, sender=User)
def refuse_second_account(sender: type[User], instance: User, **kwargs: object) -> None:
    if instance._state.adding and User.objects.exclude(pk=instance.pk).exists():
        raise OwnerExists("the owner account already exists; only one account is allowed")
