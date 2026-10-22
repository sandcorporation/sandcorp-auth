"""Signing keys: create, rotate, list, and publish (JWKS) the Ed25519 keys that sign tokens.

Private keys are stored only as Fernet tokens (`services.crypto`).
"""

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, TypedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.conf import settings
from django.db import transaction
from django.db.models import Q

from adapters.clock import get_clock
from adapters.randomness import get_randomness
from oauth.models import SigningKey
from services.crypto import decrypt_secret, encrypt_secret

ALGORITHM = "EdDSA"


class NoActiveSigningKey(Exception):
    """No active signing key: run `manage.py signing_keys create`."""


class ActiveSigningKeyExists(Exception):
    """`create` refused because a key is already active (use `rotate`)."""


class PublicJwk(TypedDict):
    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    kid: str
    x: str
    alg: Literal["EdDSA"]
    use: Literal["sig"]


class PublicJwkSet(TypedDict):
    keys: list[PublicJwk]


@dataclass(frozen=True)
class ActiveKey:
    kid: str
    private_key: Ed25519PrivateKey


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def random_token(n_bytes: int = 16) -> str:
    """A urlsafe random string from the randomness adapter (kid, jti)."""
    return b64url(get_randomness().token_bytes(n_bytes))


def _new_key(now: datetime) -> SigningKey:
    seed = get_randomness().token_bytes(32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return SigningKey.objects.create(
        kid=random_token(),
        public_key=b64url(public_raw),
        private_key_encrypted=encrypt_secret(seed),
        created_at=now,
        active=True,
    )


def create_signing_key() -> SigningKey:
    """Create the first active key. Raises ActiveSigningKeyExists if one is active."""
    with transaction.atomic():
        if SigningKey.objects.select_for_update().filter(active=True).exists():
            raise ActiveSigningKeyExists
        return _new_key(get_clock().now())


def rotate_signing_key() -> SigningKey:
    """Make a new active key and retire the current one (if any) as of now."""
    now = get_clock().now()
    with transaction.atomic():
        SigningKey.objects.select_for_update().filter(active=True).update(
            active=False, retired_at=now
        )
        return _new_key(now)


def list_signing_keys() -> list[SigningKey]:
    return list(SigningKey.objects.order_by("-created_at", "-id"))


def active_signing_key() -> ActiveKey:
    key = SigningKey.objects.filter(active=True).first()
    if key is None:
        raise NoActiveSigningKey("no active signing key; run `manage.py signing_keys create`")
    seed = decrypt_secret(bytes(key.private_key_encrypted))
    return ActiveKey(kid=key.kid, private_key=Ed25519PrivateKey.from_private_bytes(seed))


def published_jwks() -> PublicJwkSet:
    """The active key plus keys retired within ACCESS_TOKEN_LIFETIME (their tokens may live)."""
    grace_start = get_clock().now() - settings.ACCESS_TOKEN_LIFETIME
    keys = SigningKey.objects.filter(Q(active=True) | Q(retired_at__gte=grace_start)).order_by(
        "-active", "-created_at", "-id"
    )
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": key.kid,
                "x": key.public_key,
                "alg": "EdDSA",
                "use": "sig",
            }
            for key in keys
        ]
    }
