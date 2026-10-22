from typing import TYPE_CHECKING

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from django.http import HttpRequest

if TYPE_CHECKING:
    _UserAdmin = UserAdmin[User]
else:  # UserAdmin is generic only in django-stubs
    _UserAdmin = UserAdmin

admin.site.unregister(User)


@admin.register(User)
class OwnerAdmin(_UserAdmin):
    """The owner account is created by `manage.py owner create`; admin cannot add a second."""

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
