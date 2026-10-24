from datetime import datetime

from authlib.oauth2.rfc6749 import AuthorizationCodeMixin, ClientMixin, TokenMixin
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.hashers import check_password
from django.db import models
from django.db.models import Case, Q, Value, When

from adapters.clock import get_clock
from services.redirect_uris import ALLOWED_GRANT_TYPES


def _live_marker(condition: Q) -> models.GeneratedField:
    """A stored column that is 1 while `condition` holds and NULL otherwise.

    MySQL has no partial (conditional) unique indexes, so "at most one row where `condition`"
    is a plain unique constraint over this column: NULLs never collide in a unique index.
    """
    return models.GeneratedField(
        expression=Case(When(condition, then=Value(1)), default=Value(None)),
        output_field=models.SmallIntegerField(null=True),
        db_persist=True,
    )


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
    active_marker = _live_marker(Q(active=True))

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["active_marker"], name="oauth_signingkey_single_active")
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

    # ascii_bin: compared byte for byte (case-sensitive), and 2048 ASCII bytes fit MySQL's
    # 3072-byte unique index limit (utf8mb4 would need 8192). Non-ASCII ids never reach the DB
    # (services.clients.find_client).
    client_id = models.CharField(max_length=2048, unique=True, db_collation="ascii_bin")
    name = models.CharField(max_length=200)
    redirect_uris = models.JSONField(default=list)
    kind = models.CharField(max_length=16, choices=Kind.choices, default=Kind.PUBLIC)
    # Django password hash of the client secret (confidential clients only).
    secret_hash = models.CharField(max_length=256, blank=True, default="")
    registered_via = models.CharField(max_length=8, choices=Via.choices)
    created_at = models.DateTimeField()
    active = models.BooleanField(default=True)
    # "Allows members" (ADR 0003): only then may a member's session get a code or a token here.
    allows_members = models.BooleanField(
        "일반 사용자 허용",
        default=False,
        help_text="켜면 대표 말고 일반 사용자(소셜 로그인 계정)도 이 클라이언트로 로그인한다. "
        "일반 사용자는 login·openid·profile·email 스코프만 받는다.",
    )
    # user.deleted webhook (#39, ADR 0004): where to POST it, and the HMAC secret encrypted
    # with SIGNING_KEY_ENCRYPTION_KEY (HMAC needs the secret itself, so it is not hashed).
    webhook_url = models.URLField(
        "웹훅 URL",
        max_length=500,
        blank=True,
        default="",
        help_text="탈퇴한 사용자를 알리는 user.deleted 웹훅을 받을 https 주소. "
        "비우면 보내지 않는다.",
    )
    webhook_secret_encrypted = models.BinaryField(null=True, blank=True, editable=False)
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


class Consent(models.Model):
    """The owner's permission for one client to act on one resource with a set of scopes.

    Alive while `revoked_at` is null; one live consent per (owner, client, resource). A request
    whose scopes are all in the live consent is answered without asking again.
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="consents")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="consents")
    # Sorted scope names: `resource`'s scopes, plus login info scopes (openid, profile, email;
    # services.oidc) when they were asked for together with a resource.
    scopes = models.JSONField(default=list)
    granted_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    live_marker = _live_marker(Q(revoked_at__isnull=True))

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "client", "resource", "live_marker"],
                name="oauth_consent_single_live",
            )
        ]

    def __str__(self) -> str:
        return f"{self.client.name} → {self.resource.name} [{' '.join(self.scopes)}]"

    def covers(self, scopes: list[str]) -> bool:
        return set(scopes) <= set(self.scopes)


class AuthorizationCode(AuthorizationCodeMixin, models.Model):  # type: ignore[misc]  # no stubs
    """A one-time code the client exchanges for tokens. Only the SHA-256 of the code is stored.

    Bound to the client, redirect URI, PKCE challenge, resource, scopes and the consent that
    allowed it. Lives `AUTHORIZATION_CODE_LIFETIME`; `used_at` is set when it is exchanged.
    """

    code_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="+")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    consent = models.ForeignKey(Consent, on_delete=models.CASCADE, related_name="codes")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="+")
    redirect_uri = models.CharField(max_length=2048)
    scope = models.CharField(max_length=1000)
    code_challenge = models.CharField(max_length=128)
    code_challenge_method = models.CharField(max_length=8)
    # OpenID Connect `nonce` from the authorization request, copied into the ID token.
    nonce = models.CharField(max_length=255, blank=True, default="")
    # When the owner last logged in (password + TOTP) before the code was issued.
    auth_time = models.DateTimeField()
    created_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.client.name} {self.created_at:%Y-%m-%d %H:%M:%S}"

    @property
    def expires_at(self) -> datetime:
        lifetime = settings.AUTHORIZATION_CODE_LIFETIME
        expires: datetime = self.created_at + lifetime
        return expires

    def is_expired(self) -> bool:
        return get_clock().now() >= self.expires_at

    # authlib AuthorizationCodeMixin

    def get_redirect_uri(self) -> str:
        return self.redirect_uri

    def get_scope(self) -> str:
        return self.scope

    def get_auth_time(self) -> int:
        return int(self.auth_time.timestamp())

    def get_nonce(self) -> str | None:
        return self.nonce or None


class RefreshTokenFamily(models.Model):
    """The refresh tokens that descend from one consent. One live family per consent: the
    first code exchange of a consent opens it, later exchanges add tokens to it. Revoking the
    family (code reuse, refresh token reuse, consent revocation) kills every token in it."""

    consent = models.ForeignKey(Consent, on_delete=models.CASCADE, related_name="families")
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="+")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="+")
    created_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=40, blank=True)
    live_marker = _live_marker(Q(revoked_at__isnull=True))

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["consent", "live_marker"], name="oauth_refresh_family_single_live"
            )
        ]

    def __str__(self) -> str:
        return f"{self.client.name} → {self.resource.name} {self.created_at:%Y-%m-%d %H:%M:%S}"


class RefreshToken(TokenMixin, models.Model):  # type: ignore[misc]  # authlib has no type stubs
    """One refresh token (opaque; only its SHA-256 is stored). Lives `REFRESH_TOKEN_LIFETIME`.
    Dead once revoked, replaced (`replaced_by`, set by rotation) or its family is revoked."""

    family = models.ForeignKey(RefreshTokenFamily, on_delete=models.CASCADE, related_name="tokens")
    token_hash = models.CharField(max_length=64, unique=True)
    scope = models.CharField(max_length=1000)
    # jti of the access token issued together with this refresh token.
    jti = models.CharField(max_length=64, blank=True)
    # The owner's login time behind the code this token descends from (the ID token's
    # `auth_time` on refresh). Null for tokens issued before OpenID Connect was added.
    auth_time = models.DateTimeField(null=True, blank=True)
    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    replaced_by = models.OneToOneField(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="replaces"
    )

    def __str__(self) -> str:
        return f"{self.family} {self.issued_at:%Y-%m-%d %H:%M:%S}"

    # authlib TokenMixin (times from get_clock(), not time.time())

    def check_client(self, client: Client) -> bool:
        return bool(self.family.client_id == client.pk)

    def get_scope(self) -> str:
        return self.scope

    def get_expires_in(self) -> int:
        return int((self.expires_at - self.issued_at).total_seconds())

    def is_expired(self) -> bool:
        return get_clock().now() >= self.expires_at

    def is_revoked(self) -> bool:
        return (
            self.revoked_at is not None
            or self.replaced_by_id is not None
            or self.family.revoked_at is not None
        )

    def get_user(self) -> AbstractBaseUser:
        user: AbstractBaseUser = self.family.user
        return user

    def get_client(self) -> Client:
        return self.family.client


class WebhookDelivery(models.Model):
    """One webhook event for one client, waiting to be sent or sent (#39, ADR 0004).

    `body` is the exact JSON that is signed and sent on every attempt (same `event_id`, so the
    receiver can drop a repeat). `webhooks deliver` sends the rows whose `next_attempt_at` has
    come; a 2xx answer sets `delivered_at`, a failure schedules the next attempt, and after the
    last one `gave_up_at` is set.
    """

    event_id = models.CharField(max_length=26, unique=True, db_collation="ascii_bin")
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="webhook_deliveries")
    event_type = models.CharField(max_length=32)
    body = models.TextField()
    created_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=200, blank=True, default="")
    delivered_at = models.DateTimeField(null=True, blank=True)
    gave_up_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "웹훅 전송"
        verbose_name_plural = "웹훅 전송"

    def __str__(self) -> str:
        return f"{self.event_type} {self.event_id} → {self.client_id}"
