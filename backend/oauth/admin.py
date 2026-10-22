from typing import TYPE_CHECKING

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest

from oauth.models import Client, Resource, Scope

if TYPE_CHECKING:
    _ResourceAdmin = admin.ModelAdmin[Resource]
    _ClientAdmin = admin.ModelAdmin[Client]
    _ScopeInline = admin.TabularInline[Scope, Resource]
else:  # generic only in django-stubs
    _ResourceAdmin = admin.ModelAdmin
    _ClientAdmin = admin.ModelAdmin
    _ScopeInline = admin.TabularInline


class ScopeInline(_ScopeInline):
    model = Scope
    extra = 1
    fields = ["name", "description"]


@admin.register(Resource)
class ResourceAdmin(_ResourceAdmin):
    """Resources (token audiences) with their scopes edited inline."""

    list_display = ["name", "url"]
    inlines = [ScopeInline]


@admin.register(Client)
class ClientAdmin(_ClientAdmin):
    """Clients are registered by CIMD/DCR (or by a later admin flow); here they are seen,
    revoked (inactive) and, for CIMD, have their cached metadata document dropped."""

    list_display = ["name", "client_id", "registered_via", "kind", "active", "created_at"]
    list_filter = ["registered_via", "kind", "active"]
    search_fields = ["name", "client_id"]
    ordering = ["-created_at"]
    readonly_fields = [
        "client_id",
        "registered_via",
        "created_at",
        "secret_hash",
        "metadata_fetched_at",
        "metadata_expires_at",
        "metadata_document",
    ]
    actions = ["deactivate", "clear_cimd_cache"]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @admin.action(description="선택한 클라이언트 폐기(비활성)")
    def deactivate(self, request: HttpRequest, queryset: QuerySet[Client]) -> None:
        count = queryset.update(active=False)
        self.message_user(request, f"클라이언트 {count}개를 폐기했습니다.")

    @admin.action(description="CIMD 캐시 비우기(다음 사용 때 문서를 다시 가져옴)")
    def clear_cimd_cache(self, request: HttpRequest, queryset: QuerySet[Client]) -> None:
        count = queryset.filter(registered_via=Client.Via.CIMD).update(metadata_expires_at=None)
        self.message_user(request, f"CIMD 클라이언트 {count}개의 캐시를 비웠습니다.")
