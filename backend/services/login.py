"""Login decisions, request limiting and audit logging, gathered in one place.

The views only translate these answers into redirects; they never judge credentials themselves.
Two limits apply to every attempt:

- per address (`login:ip:<ip>`, rule `login`): 5 failures in 15 minutes block the IP for 15
  minutes;
- per account (`login_account:user:<username>`, rule `login_account`): no lock, because anyone
  knows the owner's username and could keep him out. Each consecutive failure only delays the
  next attempt (1, 2, 4 ... 60 seconds).

While either refuses (`login_blocked`) the views must not judge credentials at all, so timing
and messages tell nothing about the password.
"""

from django.contrib.auth import authenticate
from django.contrib.auth.models import User

from services import audit, throttle
from services.totp import accept_code, confirmed_device, enrollment_device

IP_RULE = "login"
ACCOUNT_RULE = "login_account"


def _ip_key(ip: str) -> str:
    return f"ip:{ip}"


def _account_key(username: str) -> str:
    return f"user:{username}"


def login_blocked(username: str, ip: str) -> int:
    """Seconds until this address and account may try again; 0 when they may try now.
    A refusal is audited: `login.locked` when the address is blocked, else `login.delayed`."""
    ip_wait = throttle.check(IP_RULE, _ip_key(ip)).retry_after
    account_wait = throttle.check(ACCOUNT_RULE, _account_key(username)).retry_after
    if ip_wait:
        audit.record(audit.LOGIN_LOCKED, actor=username, ip=ip, detail={"refused": True})
    elif account_wait:
        audit.record(
            audit.LOGIN_DELAYED, actor=username, ip=ip, detail={"wait_seconds": account_wait}
        )
    return max(ip_wait, account_wait)


def login_failed(kind: str, username: str, ip: str, step: str) -> int:
    """Count and audit one failed attempt; seconds of the address block it caused (0 if none).
    The account delay it starts is not reported here: the next attempt meets it."""
    audit.record(kind, actor=username, ip=ip, detail={"step": step})
    throttle.backoff_hit(ACCOUNT_RULE, _account_key(username))
    decision = throttle.hit(IP_RULE, _ip_key(ip))
    if decision.allowed:
        return 0
    audit.record(
        audit.LOGIN_LOCKED,
        actor=username,
        ip=ip,
        detail={"scope": "ip", "step": step, "seconds": decision.retry_after},
    )
    return decision.retry_after


def login_succeeded(user: User, ip: str, *, enrolled_now: bool) -> None:
    """Password + TOTP passed: audit it and clear this account's and address's counters."""
    username = user.get_username()
    if enrolled_now:
        audit.record(audit.LOGIN_TOTP_ENROLLED, actor=username, ip=ip)
    audit.record(audit.LOGIN_SUCCEEDED, actor=username, ip=ip)
    throttle.reset(IP_RULE, _ip_key(ip))
    throttle.reset(ACCOUNT_RULE, _account_key(username))


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
