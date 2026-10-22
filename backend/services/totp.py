"""TOTP (RFC 6238, 30 s steps, 6 digits) with pyotp; time always comes from `get_clock()`."""

import base64
import hmac
import io
from datetime import timedelta

import pyotp
import qrcode
import qrcode.image.svg
from django.contrib.auth.models import User
from django.db import transaction

from accounts.models import TotpDevice
from adapters.clock import get_clock
from adapters.randomness import get_randomness
from services.crypto import decrypt_secret, encrypt_secret

ISSUER = "Sandcorp Auth"
STEP_SECONDS = 30
# Accept the previous and next step too (clock drift between phone and server).
DRIFT_STEPS = 1


def _totp(device: TotpDevice) -> pyotp.TOTP:
    secret = decrypt_secret(bytes(device.secret_encrypted)).decode()
    return pyotp.TOTP(secret, interval=STEP_SECONDS)


def confirmed_device(user: User) -> TotpDevice | None:
    return TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).first()


def is_enrolled(user: User) -> bool:
    return TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).exists()


def enrollment_device(user: User) -> TotpDevice:
    """The unconfirmed device to enroll (created with a new secret if there is none)."""
    device = TotpDevice.objects.filter(user=user).first()
    if device is not None:
        return device
    secret = base64.b32encode(get_randomness().token_bytes(20)).decode()
    return TotpDevice.objects.create(
        user=user, secret_encrypted=encrypt_secret(secret.encode()), created_at=get_clock().now()
    )


def secret_of(device: TotpDevice) -> str:
    return decrypt_secret(bytes(device.secret_encrypted)).decode()


def provisioning_uri(device: TotpDevice) -> str:
    return _totp(device).provisioning_uri(name=device.user.get_username(), issuer_name=ISSUER)


def qr_svg(text: str) -> str:
    image = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
    out = io.BytesIO()
    image.save(out)
    return out.getvalue().decode()


def current_code(device: TotpDevice) -> str:
    """The code an authenticator shows right now (tests use it with the frozen clock)."""
    return _totp(device).at(get_clock().now())


def accept_code(device: TotpDevice, code: str) -> bool:
    """True if `code` matches a step within drift that is newer than the last accepted one;
    records that step so the same code cannot be used twice."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return False
    now = get_clock().now()
    with transaction.atomic():
        locked = TotpDevice.objects.select_for_update().get(pk=device.pk)
        totp = _totp(locked)
        for offset in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
            at = now + timedelta(seconds=offset * STEP_SECONDS)
            counter = totp.timecode(at)
            if locked.last_used_counter is not None and counter <= locked.last_used_counter:
                continue
            if hmac.compare_digest(totp.at(at), code):
                locked.last_used_counter = counter
                if locked.confirmed_at is None:
                    locked.confirmed_at = now
                locked.save(update_fields=["last_used_counter", "confirmed_at"])
                return True
    return False
