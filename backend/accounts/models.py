from django.conf import settings
from django.db import models


class TotpDevice(models.Model):
    """The owner's TOTP authenticator. `confirmed_at` is null until a first code is accepted:
    until then the account is "before TOTP enrollment" and may only reach the setup screen."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_device"
    )
    secret_encrypted = models.BinaryField()
    created_at = models.DateTimeField()
    confirmed_at = models.DateTimeField(null=True, blank=True)
    # Time-step counter of the last accepted code; codes at or before it are refused (no replay).
    last_used_counter = models.BigIntegerField(null=True, blank=True)

    def __str__(self) -> str:
        state = "등록됨" if self.confirmed_at else "등록 전"
        return f"TOTP 장치({state})"


class Member(models.Model):
    """Marks a Django User as a Sandcorp member (ADR 0003): signs in with a social login only,
    `username` is its opaque `sub` (`m_` + ULID), no password, never staff. The owner has no
    Member row. `email_verified` speaks for `User.email` (empty when there is none)."""

    class Status(models.TextChoices):
        # Made by a first social login; becomes active once the terms are agreed to (#37).
        PENDING_TERMS = "pending_terms", "동의 대기"
        ACTIVE = "active", "활성"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="member"
    )
    created_at = models.DateTimeField()
    email_verified = models.BooleanField(default=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING_TERMS)

    def __str__(self) -> str:
        return f"일반 사용자 {self.user_id}"


class ExternalIdentity(models.Model):
    """A social login account (Google, Kakao) linked to a Sandcorp account. (provider,
    provider_sub) belongs to one account only; an account may have several identities. What
    the provider said at link time is kept as it said it; nothing is merged automatically."""

    class Provider(models.TextChoices):
        GOOGLE = "google", "Google"
        KAKAO = "kakao", "Kakao"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="identities"
    )
    provider = models.CharField(max_length=16, choices=Provider.choices)
    provider_sub = models.CharField(max_length=255)
    email = models.EmailField(blank=True, default="")
    email_verified = models.BooleanField(default=False)
    display_name = models.CharField(max_length=150, blank=True, default="")
    linked_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "provider_sub"], name="accounts_identity_provider_sub_uniq"
            )
        ]

    def __str__(self) -> str:
        return f"{self.get_provider_display()} {self.provider_sub}"
