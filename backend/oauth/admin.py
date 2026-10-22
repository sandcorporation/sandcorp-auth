from typing import TYPE_CHECKING

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest

from core.http import client_ip
from oauth.models import (
    AuthorizationCode,
    Client,
    Consent,
    RefreshToken,
    RefreshTokenFamily,
    Resource,
    Scope,
)
from oauth.tokens import revoke_family
from services import audit
from services.consents import revoke_consent

if TYPE_CHECKING:
    _ResourceAdmin = admin.ModelAdmin[Resource]
    _ClientAdmin = admin.ModelAdmin[Client]
    _ScopeInline = admin.TabularInline[Scope, Resource]
    _ConsentAdmin = admin.ModelAdmin[Consent]
    _AuthorizationCodeAdmin = admin.ModelAdmin[AuthorizationCode]
    _RefreshTokenFamilyAdmin = admin.ModelAdmin[RefreshTokenFamily]
    _RefreshTokenAdmin = admin.ModelAdmin[RefreshToken]
else:  # generic only in django-stubs
    _RefreshTokenFamilyAdmin = admin.ModelAdmin
    _RefreshTokenAdmin = admin.ModelAdmin
    _ConsentAdmin = admin.ModelAdmin
    _AuthorizationCodeAdmin = admin.ModelAdmin
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


class ReadOnlyAdminMixin:
    """Rows written only by the authorization flow: admin lists and shows them."""

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: object = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: object = None) -> bool:
        return False


@admin.register(Consent)
class ConsentAdmin(ReadOnlyAdminMixin, _ConsentAdmin):
    """What the owner allowed: when, which client, which resource and scopes. Revoking a
    consent cuts its refresh token families; the next /authorize asks the owner again."""

    list_display = ["client", "resource", "scope_list", "granted_at", "revoked_at", "is_live"]
    list_filter = ["resource", ("revoked_at", admin.EmptyFieldListFilter)]
    search_fields = ["client__name", "client__client_id"]
    ordering = ["-granted_at"]
    list_select_related = ["client", "resource"]
    actions = ["revoke"]

    @admin.action(description="선택한 동의 폐기(리프레시 토큰 패밀리도 폐기)")
    def revoke(self, request: HttpRequest, queryset: QuerySet[Consent]) -> None:
        actor = request.user.get_username()
        ip = client_ip(request)
        count = sum(
            revoke_consent(consent, reason="consent_revoked", actor=actor, ip=ip)
            for consent in queryset.filter(revoked_at__isnull=True)
        )
        self.message_user(request, f"동의 {count}개를 폐기했습니다.")

    @admin.display(description="스코프")
    def scope_list(self, obj: Consent) -> str:
        return " ".join(obj.scopes)

    @admin.display(description="살아 있음", boolean=True)
    def is_live(self, obj: Consent) -> bool:
        return obj.revoked_at is None


@admin.register(AuthorizationCode)
class AuthorizationCodeAdmin(ReadOnlyAdminMixin, _AuthorizationCodeAdmin):
    """Issued authorization codes (hash only), for following a consent to its codes."""

    list_display = ["client", "resource", "scope", "created_at", "used_at"]
    list_filter = ["resource"]
    ordering = ["-created_at"]
    list_select_related = ["client", "resource"]
    exclude = ["code_hash"]


@admin.register(RefreshTokenFamily)
class RefreshTokenFamilyAdmin(ReadOnlyAdminMixin, _RefreshTokenFamilyAdmin):
    """Refresh token families, one live per consent. Revoking one cuts all its tokens; the
    consent stays, so the client can get a new family with a new authorization code."""

    list_display = ["client", "resource", "created_at", "revoked_at", "revoked_reason"]
    list_filter = ["resource", ("revoked_at", admin.EmptyFieldListFilter)]
    search_fields = ["client__name", "client__client_id"]
    ordering = ["-created_at"]
    list_select_related = ["client", "resource"]
    actions = ["revoke"]

    @admin.action(description="선택한 패밀리 폐기")
    def revoke(self, request: HttpRequest, queryset: QuerySet[RefreshTokenFamily]) -> None:
        actor = request.user.get_username()
        ip = client_ip(request)
        families = list(
            queryset.filter(revoked_at__isnull=True).select_related("client", "resource")
        )
        for family in families:
            revoke_family(family, "revoked_by_admin")
            audit.record(
                audit.TOKEN_REVOKED,
                actor=actor,
                client_id=family.client.client_id,
                ip=ip,
                detail={
                    "resource": family.resource.url,
                    "family": family.pk,
                    "reason": "revoked_by_admin",
                },
            )
        self.message_user(request, f"패밀리 {len(families)}개를 폐기했습니다.")


@admin.register(RefreshToken)
class RefreshTokenAdmin(ReadOnlyAdminMixin, _RefreshTokenAdmin):
    """Issued refresh tokens (hash only): when issued, until when, whether revoked/replaced."""

    list_display = ["family", "scope", "issued_at", "expires_at", "revoked_at", "replaced_by"]
    list_filter = [("revoked_at", admin.EmptyFieldListFilter)]
    ordering = ["-issued_at"]
    list_select_related = ["family__client", "family__resource"]
    exclude = ["token_hash"]
