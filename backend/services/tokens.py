"""Access token issuance: EdDSA-signed JWTs (docs/resource-server-token-validation.md §2)."""

from collections.abc import Sequence

import jwt
from django.conf import settings

from adapters.clock import get_clock
from services.signing import ALGORITHM, active_signing_key, random_token


def issue_access_token(*, sub: str, audience: str, client_id: str, scopes: Sequence[str]) -> str:
    """Sign an access token with the active key. Raises NoActiveSigningKey if there is none."""
    key = active_signing_key()
    iat = int(get_clock().now().timestamp())
    claims: dict[str, str | int] = {
        "iss": settings.SITE_URL,
        "sub": sub,
        "aud": audience,
        "client_id": client_id,
        "scope": " ".join(scopes),
        "iat": iat,
        "exp": iat + int(settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
        "jti": random_token(),
    }
    return jwt.encode(
        claims, key.private_key, algorithm=ALGORITHM, headers={"kid": key.kid, "typ": "JWT"}
    )
