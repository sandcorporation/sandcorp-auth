from typing import TYPE_CHECKING

from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from django.db.models import QuerySet
from django.http import HttpRequest

from accounts.models import Member, TermsAgreement, TermsDocument
from adapters.clock import get_clock
from core.http import client_ip
from services.terms import record_registered

if TYPE_CHECKING:
    _UserAdmin = UserAdmin[User]
    _TermsDocumentAdmin = admin.ModelAdmin[TermsDocument]
    _TermsAgreementAdmin = admin.ModelAdmin[TermsAgreement]
else:  # generic only in django-stubs
    _UserAdmin = UserAdmin
    _TermsDocumentAdmin = admin.ModelAdmin
    _TermsAgreementAdmin = admin.ModelAdmin

admin.site.unregister(User)

OWNER_FILTER = "owner"


def _member(user: User) -> Member | None:
    try:
        return user.member
    except Member.DoesNotExist:
        return None


class AccountStatusFilter(admin.SimpleListFilter):
    """대표 / a member status (#145)."""

    title = "회원 상태"
    parameter_name = "account_status"

    def lookups(
        self, request: HttpRequest, model_admin: admin.ModelAdmin[User]
    ) -> list[tuple[str, str]]:
        return [(OWNER_FILTER, "대표"), *Member.Status.choices]

    def queryset(self, request: HttpRequest, queryset: QuerySet[User]) -> QuerySet[User]:
        value = self.value()
        if value == OWNER_FILTER:
            return queryset.filter(member__isnull=True)
        if value in Member.Status.values:
            return queryset.filter(member__status=value)
        return queryset


@admin.register(User)
class OwnerAdmin(_UserAdmin):
    """The owner account is created by `manage.py owner create`; admin cannot add a second.
    The list shows the owner and members with their account kind and member status (#145)."""

    list_display = ("username", "email", "account_kind", "member_status", "is_active")
    list_filter = (AccountStatusFilter, "is_active")
    list_select_related = ("member",)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @admin.display(description="계정 종류")
    def account_kind(self, obj: User) -> str:
        return "일반 사용자" if _member(obj) is not None else "대표"

    @admin.display(description="회원 상태")
    def member_status(self, obj: User) -> str:
        member = _member(obj)
        return "-" if member is None else member.get_status_display()


@admin.register(TermsDocument)
class TermsDocumentAdmin(_TermsDocumentAdmin):
    """New versions are added here (or `manage.py terms add`); a registered version is never
    edited or deleted, since agreements point at it — a change is a new version (#37)."""

    list_display = ("kind", "version", "effective_date", "url", "created_at")
    list_filter = ("kind",)
    ordering = ("kind", "-effective_date", "-id")
    fields = ("kind", "version", "effective_date", "url")

    def has_change_permission(self, request: HttpRequest, obj: TermsDocument | None = None) -> bool:
        return obj is None and super().has_change_permission(request, obj)

    def has_delete_permission(self, request: HttpRequest, obj: TermsDocument | None = None) -> bool:
        return False

    def save_model(
        self,
        request: HttpRequest,
        obj: TermsDocument,
        form: forms.ModelForm[TermsDocument],
        change: bool,
    ) -> None:
        obj.created_at = get_clock().now()
        super().save_model(request, obj, form, change)
        record_registered(obj, actor=request.user.get_username(), ip=client_ip(request))


@admin.register(TermsAgreement)
class TermsAgreementAdmin(_TermsAgreementAdmin):
    """Read only: agreements are made by members on the terms screen."""

    list_display = ("user", "document", "agreed_at", "age_confirmed")
    list_filter = ("document",)
    search_fields = ("user__username",)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(
        self, request: HttpRequest, obj: TermsAgreement | None = None
    ) -> bool:
        return False

    def has_delete_permission(
        self, request: HttpRequest, obj: TermsAgreement | None = None
    ) -> bool:
        return False
