"""The audit log: `record(kind, ...)` writes one `audit.AuditEvent` at `get_clock().now()`.

`kind` is a free string; the ones in use are the constants below (later tickets add theirs,
e.g. `token.issued`). Never put a secret (password, TOTP code, token) in `detail`: keys that
look like one are refused.
"""

from collections.abc import Mapping
from typing import Final

from adapters.clock import get_clock
from audit.models import AuditEvent

type JSON = str | int | float | bool | None | list[JSON] | dict[str, JSON]

LOGIN_PASSWORD_FAILED: Final = "login.password_failed"
LOGIN_TOTP_FAILED: Final = "login.totp_failed"
LOGIN_LOCKED: Final = "login.locked"
LOGIN_DELAYED: Final = "login.delayed"
LOGIN_SUCCEEDED: Final = "login.succeeded"
LOGIN_TOTP_ENROLLED: Final = "login.totp_enrolled"
LOGOUT: Final = "logout"
CLIENT_REGISTERED: Final = "client.registered"
CLIENT_CIMD_REJECTED: Final = "client.cimd_rejected"
CLIENT_CREATED: Final = "client.created"
CLIENT_SECRET_ROTATED: Final = "client.secret_rotated"
CLIENT_MEMBERS_CHANGED: Final = "client.members_changed"
CONSENT_GRANTED: Final = "consent.granted"
CONSENT_DENIED: Final = "consent.denied"
AUTHORIZATION_CODE_ISSUED: Final = "authorization_code.issued"
TOKEN_ISSUED: Final = "token.issued"
TOKEN_CODE_REUSE_DETECTED: Final = "token.code_reuse_detected"
TOKEN_REFRESHED: Final = "token.refreshed"
TOKEN_REUSE_DETECTED: Final = "token.reuse_detected"
TOKEN_REVOKED: Final = "token.revoked"
CONSENT_REVOKED: Final = "consent.revoked"
SOCIAL_LOGIN_SUCCEEDED: Final = "login.social_succeeded"
SOCIAL_LOGIN_FAILED: Final = "login.social_failed"
MEMBER_CREATED: Final = "member.created"
IDENTITY_LINKED: Final = "identity.linked"
IDENTITY_UNLINKED: Final = "identity.unlinked"
MEMBER_EMAIL_CHANGED: Final = "member.email_changed"
TERMS_REGISTERED: Final = "terms.registered"
TERMS_AGREED: Final = "terms.agreed"
CLIENT_WEBHOOK_CHANGED: Final = "client.webhook_changed"
MEMBER_WITHDRAWN: Final = "member.withdrawn"
MEMBER_PURGED: Final = "member.purged"

SECRET_KEYS: Final = frozenset({"password", "code", "token", "secret", "otp"})


def record(
    kind: str,
    *,
    actor: str = "",
    client_id: str = "",
    ip: str = "",
    detail: Mapping[str, JSON] | None = None,
) -> AuditEvent:
    detail = dict(detail or {})
    leaked = [key for key in detail if any(word in key.lower() for word in SECRET_KEYS)]
    if leaked:
        raise ValueError(f"audit detail must not carry secrets: {leaked}")
    return AuditEvent.objects.create(
        at=get_clock().now(),
        kind=kind,
        actor=actor[:150],
        client_id=client_id,
        ip=ip,
        detail=detail,
    )
