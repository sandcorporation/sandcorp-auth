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
