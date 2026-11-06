from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from django import forms
from django.contrib import admin, messages
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import URLPattern, path, reverse

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
from services.confidential_clients import (
    InvalidRedirectUri,
    NotConfidential,
    confidential_redirect_uris,
    create_confidential_client,
    rotate_client_secret,
)
from services.consents import revoke_consent
from services.members import record_members_changed, record_scope_members_changed
from services.redirect_uris import valid_redirect_uri
from services.webhooks import InvalidWebhookUrl, set_webhook

if TYPE_CHECKING:
    _ResourceAdmin = admin.ModelAdmin[Resource]
    _ClientAdmin = admin.ModelAdmin[Client]
    _ClientForm = forms.ModelForm[Client]
    from django.contrib.admin.options import _FieldsetSpec

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
    _ClientForm = forms.ModelForm
    _ScopeInline = admin.TabularInline


def _ascii_safe(fields: Sequence[str], request: HttpRequest) -> list[str]:
    """Drop `client_id` lookups from a non-ASCII search: the column is ascii_bin, and MySQL
    refuses to compare it with a term it cannot convert (3854). No client_id matches it anyway."""
    if request.GET.get("q", "").isascii():
        return list(fields)
    return [field for field in fields if not field.endswith("client_id")]


class ScopeInline(_ScopeInline):
    """`members_allowed` (#47): `Scope.clean` refuses it on `admin`·`editor`."""

    model = Scope
    extra = 1
    fields = ["name", "description", "members_allowed"]


@admin.register(Resource)
class ResourceAdmin(_ResourceAdmin):
    """Resources (token audiences) with their scopes edited inline."""

    list_display = ["name", "url"]
    inlines = [ScopeInline]

    def save_formset(
        self,
        request: HttpRequest,
        form: forms.ModelForm[Resource],
        formset: forms.BaseModelFormSet[Scope, forms.ModelForm[Scope]],
        change: bool,
    ) -> None:
        super().save_formset(request, form, formset, change)
        deleted = getattr(formset, "deleted_forms", [])
        for scope_form in formset.forms:
            scope = scope_form.instance
            if (
                scope.pk
                and "members_allowed" in scope_form.changed_data
                and scope_form not in deleted
            ):
                record_scope_members_changed(
                    scope, actor=request.user.get_username(), ip=client_ip(request)
                )


class ConfidentialClientAddForm(_ClientForm):
    """The admin add form: only confidential clients are added here (public ones come from
    DCR/CIMD). Name and https redirect URIs, one per line; the rest is fixed by the service."""

    redirect_uris_text = forms.CharField(
        label="리다이렉트 URI",
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="한 줄에 하나, https만. 정확히 일치해야 한다(끝 슬래시 포함).",
    )

    class Meta:
        model = Client
        fields = ["name"]

    def clean_redirect_uris_text(self) -> list[str]:
        text = self.cleaned_data["redirect_uris_text"]
        try:
            return confidential_redirect_uris(str(text).splitlines())
        except InvalidRedirectUri as error:
            raise forms.ValidationError(str(error)) from None


class ClientChangeForm(_ClientForm):
    """The admin change form: edited redirect URIs follow the registration rules, https only
    for confidential clients and the shared rule (https, or http on loopback) for public ones."""

    class Meta:
        model = Client
        fields = "__all__"

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401  # ModelForm's
        super().__init__(*args, **kwargs)
        if self.instance.kind == Client.Kind.MACHINE and "redirect_uris" in self.fields:
            self.fields["redirect_uris"].required = False

    def clean_webhook_url(self) -> str:
        url = str(self.cleaned_data.get("webhook_url") or "").strip()
        if url and not url.startswith("https://"):
            raise forms.ValidationError("웹훅 URL은 https 주소여야 합니다")
        return url

    def clean_redirect_uris(self) -> list[str]:
        uris: object = self.cleaned_data["redirect_uris"]
        if self.instance.kind == Client.Kind.MACHINE:
            # A machine client (#76) never redirects anyone.
            if uris:
                raise forms.ValidationError("기계 클라이언트에는 리다이렉트 URI가 없습니다")
            return []
        if not isinstance(uris, list) or not uris:
            raise forms.ValidationError("리다이렉트 URI 목록이 하나 이상 있어야 합니다")
        checked: list[str] = []
        for uri in uris:
            if not isinstance(uri, str):
                raise forms.ValidationError(f"리다이렉트 URI는 문자열이어야 합니다: {uri!r}")
            checked.append(uri)
        if self.instance.kind == Client.Kind.CONFIDENTIAL:
            try:
                return confidential_redirect_uris(checked)
            except InvalidRedirectUri as error:
                raise forms.ValidationError(str(error)) from None
        for uri in checked:
            if not valid_redirect_uri(uri):
                raise forms.ValidationError(
                    "리다이렉트 URI가 규칙(https, 또는 localhost·127.0.0.1·[::1]의 http)에 "
                    f"맞지 않습니다: {uri}"
                )
        return checked


@admin.register(Client)
class ClientAdmin(_ClientAdmin):
    """Public clients are registered by CIMD/DCR; here they are seen, revoked (inactive) and,
    for CIMD, have their cached metadata document dropped. Confidential clients (the sites'
    admin login) are added here: the secret is shown once in a message, then only its hash."""

    list_display = [
        "name",
        "client_id",
        "registered_via",
        "kind",
        "active",
        "allows_members",
        "created_at",
    ]
    list_filter = ["registered_via", "kind", "active", "allows_members"]
    search_fields = ["name", "client_id"]
    ordering = ["-created_at"]

    def get_search_fields(self, request: HttpRequest) -> list[str]:
        return _ascii_safe(super().get_search_fields(request), request)

    readonly_fields = [
        "client_id",
        "kind",
        "registered_via",
        "created_at",
        "secret_hash",
        "machine_resource",
        "machine_scopes",
        "metadata_fetched_at",
        "metadata_expires_at",
        "metadata_document",
    ]
    actions = ["deactivate", "clear_cimd_cache"]
    change_form_template = "admin/oauth/client/change_form.html"

    def has_add_permission(self, request: HttpRequest) -> bool:
        return True

    def get_form(
        self,
        request: HttpRequest,
        obj: Client | None = None,
        change: bool = False,
        **kwargs: Any,  # noqa: ANN401  # passed through to ModelAdmin.get_form untouched
    ) -> type[forms.ModelForm[Client]]:
        if obj is None:
            kwargs["form"] = ConfidentialClientAddForm
            kwargs["fields"] = ["name", "redirect_uris_text"]
        else:
            kwargs["form"] = ClientChangeForm
        return super().get_form(request, obj, change, **kwargs)

    def get_fieldsets(self, request: HttpRequest, obj: Client | None = None) -> _FieldsetSpec:
        if obj is None:
            return [(None, {"fields": ["name", "redirect_uris_text"]})]
        return super().get_fieldsets(request, obj)

    def get_readonly_fields(self, request: HttpRequest, obj: Client | None = None) -> list[str]:
        return [] if obj is None else list(self.readonly_fields)

    def save_model(
        self,
        request: HttpRequest,
        obj: Client,
        form: forms.ModelForm[Client],
        change: bool,
    ) -> None:
        if change:
            super().save_model(request, obj, form, change)
            if "allows_members" in form.changed_data:
                record_members_changed(
                    obj, actor=request.user.get_username(), ip=client_ip(request)
                )
            if "webhook_url" in form.changed_data:
                secret = set_webhook(
                    obj,
                    url=obj.webhook_url,
                    rotate_secret=False,
                    actor=request.user.get_username(),
                    ip=client_ip(request),
                )
                if secret is not None:
                    self._show_webhook_secret_once(request, obj, secret)
            return
        issued = create_confidential_client(
            obj.name,
            form.cleaned_data["redirect_uris_text"],
            actor=request.user.get_username(),
            ip=client_ip(request),
        )
        obj.pk = issued.client.pk
        obj.refresh_from_db()
        self._show_secret_once(
            request, issued.client, issued.secret, "기밀 클라이언트를 만들었습니다."
        )

    def get_urls(self) -> list[URLPattern]:
        rotate = path(
            "<int:object_id>/rotate-secret/",
            self.admin_site.admin_view(self.rotate_secret_view),
            name="oauth_client_rotate_secret",
        )
        rotate_webhook = path(
            "<int:object_id>/rotate-webhook-secret/",
            self.admin_site.admin_view(self.rotate_webhook_secret_view),
            name="oauth_client_rotate_webhook_secret",
        )
        return [rotate, rotate_webhook, *super().get_urls()]

    def rotate_webhook_secret_view(self, request: HttpRequest, object_id: int) -> HttpResponse:
        """POST only (a button on the change page): a new webhook signing secret, shown once."""
        client = get_object_or_404(Client, pk=object_id)
        change_url = reverse("admin:oauth_client_change", args=[client.pk])
        if request.method != "POST" or not self.has_change_permission(request, client):
            return HttpResponseNotAllowed(["POST"])
        if not client.webhook_url:
            self.message_user(request, "웹훅 URL이 없습니다.", messages.ERROR)
            return HttpResponseRedirect(change_url)
        try:
            secret = set_webhook(
                client,
                url=None,
                rotate_secret=True,
                actor=request.user.get_username(),
                ip=client_ip(request),
            )
        except InvalidWebhookUrl:  # pragma: no cover - url=None never validates
            return HttpResponseRedirect(change_url)
        if secret is not None:
            self._show_webhook_secret_once(request, client, secret)
        return HttpResponseRedirect(change_url)

    @staticmethod
    def _show_webhook_secret_once(request: HttpRequest, client: Client, secret: str) -> None:
        messages.success(
            request,
            f"웹훅 서명 비밀을 발급했습니다. client_id: {client.client_id} / webhook_secret: "
            f"{secret} — 지금 한 번만 보입니다. 옛 비밀은 이제 통하지 않습니다.",
        )

    def rotate_secret_view(self, request: HttpRequest, object_id: int) -> HttpResponse:
        """POST only (a button on the change page): a new secret, shown once."""
        client = get_object_or_404(Client, pk=object_id)
        change_url = reverse("admin:oauth_client_change", args=[client.pk])
        if request.method != "POST" or not self.has_change_permission(request, client):
            return HttpResponseNotAllowed(["POST"])
        try:
            secret = rotate_client_secret(
                client, actor=request.user.get_username(), ip=client_ip(request)
            )
        except NotConfidential:
            self.message_user(request, "공개 클라이언트에는 시크릿이 없습니다.", messages.ERROR)
            return HttpResponseRedirect(change_url)
        self._show_secret_once(
            request, client, secret, "시크릿을 새로 발급했습니다. 옛 시크릿은 이제 통하지 않습니다."
        )
        return HttpResponseRedirect(change_url)

    @staticmethod
    def _show_secret_once(request: HttpRequest, client: Client, secret: str, headline: str) -> None:
        messages.success(
            request,
            f"{headline} client_id: {client.client_id} / client_secret: {secret} — "
            "시크릿은 지금 한 번만 보입니다(저장된 것은 해시뿐). 사이트 설정에 바로 넣으세요.",
        )

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

    def get_search_fields(self, request: HttpRequest) -> list[str]:
        return _ascii_safe(super().get_search_fields(request), request)

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

    def get_search_fields(self, request: HttpRequest) -> list[str]:
        return _ascii_safe(super().get_search_fields(request), request)

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
