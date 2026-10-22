from authlib.oauth2.rfc6749 import ClientMixin
from django.contrib.auth.hashers import check_password
from django.db import models
from django.db.models import Q

from services.redirect_uris import ALLOWED_GRANT_TYPES


class SigningKey(models.Model):
    """An Ed25519 key that signs access tokens. The private half is stored Fernet-encrypted.

    Exactly one key is active (it signs new tokens). Rotation retires the active key
    (`retired_at`); a retired key stays in the JWKS for ACCESS_TOKEN_LIFETIME afterwards.
    """

    kid = models.CharField(max_length=64, unique=True)
    # base64url (no padding) of the raw 32-byte public key: the JWK `x` value.
    public_key = models.CharField(max_length=64)
    # Fernet(SIGNING_KEY_ENCRYPTION_KEY) token of the raw 32-byte private key.
    private_key_encrypted = models.BinaryField()
    created_at = models.DateTimeField()
    active = models.BooleanField(default=False)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["active"],
                condition=Q(active=True),
                name="oauth_signingkey_single_active",
            )
        ]

    def __str__(self) -> str:
        return self.kid


class Resource(models.Model):
    """A site protected by tokens. `url` is the token audience (`aud`) and `resource` value."""

    name = models.CharField(max_length=100)
    url = models.URLField(unique=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.url})"


class Scope(models.Model):
    """A permission inside one resource. `description` is what the owner reads on consent."""

    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="scopes")
    name = models.CharField(max_length=64)
    description = models.CharField(max_length=200)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["resource", "name"], name="oauth_scope_unique_name")
        ]

    def __str__(self) -> str:
        return f"{self.resource.url} {self.name}"


class Client(ClientMixin, models.Model):  # type: ignore[misc]  # authlib has no type stubs
    """A program that receives tokens on the owner's behalf.

    Registered through a Client ID Metadata Document (CIMD: `client_id` is the document URL and
    this row is the cache of that document), Dynamic Client Registration, or admin. Registration
    alone grants nothing: every token goes through the owner's consent.
    """

    class Kind(models.TextChoices):
        PUBLIC = "public", "공개"
        CONFIDENTIAL = "confidential", "기밀"

    class Via(models.TextChoices):
        CIMD = "cimd", "CIMD"
        DCR = "dcr", "DCR"
        ADMIN = "admin", "admin"

    client_id = models.CharField(max_length=2048, unique=True)
    name = models.CharField(max_length=200)
    redirect_uris = models.JSONField(default=list)
    kind = models.CharField(max_length=16, choices=Kind.choices, default=Kind.PUBLIC)
    # Django password hash of the client secret (confidential clients only).
    secret_hash = models.CharField(max_length=256, blank=True, default="")
    registered_via = models.CharField(max_length=8, choices=Via.choices)
    created_at = models.DateTimeField()
    active = models.BooleanField(default=True)
    # CIMD cache: when the document was fetched, until when it may be used without refetching,
    # and the document itself. Empty for DCR/admin clients.
    metadata_fetched_at = models.DateTimeField(null=True, blank=True)
    metadata_expires_at = models.DateTimeField(null=True, blank=True)
    metadata_document = models.JSONField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.client_id})"

    @property
    def is_public(self) -> bool:
        return self.kind == self.Kind.PUBLIC

    # authlib ClientMixin

    def get_client_id(self) -> str:
        return self.client_id

    def get_default_redirect_uri(self) -> str | None:
        uris: list[str] = self.redirect_uris
        return uris[0] if len(uris) == 1 else None

    def get_allowed_scope(self, scope: str | None) -> str:
        """Clients are not limited to a scope set: the requested `resource` decides which scope
        names exist (checked by the authorization endpoint) and the owner's consent grants them."""
        return " ".join(sorted(set((scope or "").split())))

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret: str) -> bool:
        if self.is_public or not self.secret_hash:
            return False
        return check_password(client_secret, self.secret_hash)

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        if self.is_public:
            return method == "none"
        return method in ("client_secret_basic", "client_secret_post")

    def check_response_type(self, response_type: str) -> bool:
        return response_type == "code"

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in ALLOWED_GRANT_TYPES
