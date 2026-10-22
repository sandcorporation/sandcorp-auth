"""Login decisions, request limiting and audit logging, gathered in one place.

The views only translate these answers into redirects; they never judge credentials themselves.
Every attempt is limited per account (`login:user:<username>`) and per address
(`login:ip:<ip>`) with the `login` rule of `settings.THROTTLE`. While either is blocked the
views must not judge credentials at all (`login_blocked`), so timing tells nothing.
"""

from django.contrib.auth import authenticate
from django.contrib.auth.models import User

from services import audit, throttle
from services.totp import accept_code, confirmed_device, enrollment_device

RULE = "login"


def _keys(username: str, ip: str) -> list[tuple[str, str]]:
    return [("user", f"user:{username}"), ("ip", f"ip:{ip}")]


def login_blocked(username: str, ip: str) -> int:
    """Seconds until this account or address may try again; 0 when it may try now.
    A refused attempt is audited as `login.locked`."""
    wait = max(throttle.check(RULE, key).retry_after for _, key in _keys(username, ip))
    if wait:
        audit.record(audit.LOGIN_LOCKED, actor=username, ip=ip, detail={"refused": True})
    return wait


def login_failed(kind: str, username: str, ip: str, step: str) -> int:
    """Count and audit one failed attempt; seconds of the lock it caused (0 if none)."""
    audit.record(kind, actor=username, ip=ip, detail={"step": step})
    wait = 0
    for scope, key in _keys(username, ip):
        decision = throttle.hit(RULE, key)
        if not decision.allowed:
            audit.record(
                audit.LOGIN_LOCKED,
                actor=username,
                ip=ip,
                detail={"scope": scope, "step": step, "seconds": decision.retry_after},
            )
            wait = max(wait, decision.retry_after)
    return wait


def login_succeeded(user: User, ip: str, *, enrolled_now: bool) -> None:
    """Password + TOTP passed: audit it and clear this account's and address's counters."""
    username = user.get_username()
    if enrolled_now:
        audit.record(audit.LOGIN_TOTP_ENROLLED, actor=username, ip=ip)
    audit.record(audit.LOGIN_SUCCEEDED, actor=username, ip=ip)
    for _, key in _keys(username, ip):
        throttle.reset(RULE, key)


def check_password_step(username: str, password: str) -> User | None:
    """First step: the owner whose username and password match, else None."""
    user = authenticate(None, username=username, password=password)
    return user if isinstance(user, User) else None


def check_totp_step(user: User, code: str) -> bool:
    """Second step for an enrolled owner: a fresh, correct TOTP code."""
    device = confirmed_device(user)
    return device is not None and accept_code(device, code)


def check_totp_enrollment(user: User, code: str) -> bool:
    """Enrollment: the first correct code confirms the device (and completes the login)."""
    device = enrollment_device(user)
    return device.confirmed_at is None and accept_code(device, code)
