from django.db import models
from django.db.models import Q


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
