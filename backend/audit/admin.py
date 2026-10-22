from typing import TYPE_CHECKING

from django.contrib import admin
from django.http import HttpRequest

from audit.models import AuditEvent

if TYPE_CHECKING:
    _ModelAdmin = admin.ModelAdmin[AuditEvent]
else:  # ModelAdmin is generic only in django-stubs
    _ModelAdmin = admin.ModelAdmin


@admin.register(AuditEvent)
class AuditEventAdmin(_ModelAdmin):
    """Read only: nobody adds, edits or deletes audit events from admin."""

    list_display = ["at", "kind", "actor", "client_id", "ip"]
    list_filter = ["kind", "actor", "at"]
    search_fields = ["kind", "actor", "client_id", "ip"]
    date_hierarchy = "at"
    readonly_fields = ["at", "kind", "actor", "client_id", "ip", "detail"]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: AuditEvent | None = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: AuditEvent | None = None) -> bool:
        return False
