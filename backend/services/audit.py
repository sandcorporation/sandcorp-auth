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
