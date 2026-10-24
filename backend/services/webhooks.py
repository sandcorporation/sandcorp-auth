"""Outgoing webhooks (#39, ADR 0004): today one event, `user.deleted`, sent to the clients a
withdrawn member had consented to.

- A client has a webhook URL and a secret (`set_webhook`). The secret is shown once and stored
  encrypted with SIGNING_KEY_ENCRYPTION_KEY: HMAC needs the secret itself.
- Withdrawal does not call anyone: `enqueue_user_deleted` writes one `WebhookDelivery` row per
  client in the withdrawal's transaction, and `deliver_due` (`manage.py webhooks deliver`, every
  few minutes) sends the rows that are due.
- Every attempt sends the same body, signed at send time:
  `X-Sandcorp-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
  A 2xx answer ends it; anything else is retried after `RETRY_DELAYS` and given up after
  `MAX_ATTEMPTS` attempts.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import transaction
from django.db.models import F

from adapters.clock import get_clock
from adapters.http import FetchError
from adapters.randomness import get_randomness
from adapters.webhook_http import get_webhook_http
from oauth.models import Client, WebhookDelivery
from services import audit
from services.crypto import decrypt_secret, encrypt_secret
from services.members import new_ulid

USER_DELETED: Final = "user.deleted"
SIGNATURE_HEADER: Final = "X-Sandcorp-Signature"
EVENT_HEADER: Final = "X-Sandcorp-Event"
DELIVERY_HEADER: Final = "X-Sandcorp-Delivery"
# Wait after the 1st, 2nd, ... failed attempt; after the last one there is no next attempt.
RETRY_DELAYS: Final = (
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(hours=1),
    timedelta(hours=3),
    timedelta(hours=6),
    timedelta(hours=12),
    timedelta(hours=24),
)
MAX_ATTEMPTS: Final = len(RETRY_DELAYS) + 1
# A claimed row is not picked again for this long (a sender that died mid-attempt).
CLAIM_LEASE: Final = timedelta(minutes=10)
SECRET_BYTES: Final = 32


class InvalidWebhookUrl(Exception):
    pass


def set_webhook(
    client: Client, *, url: str | None, rotate_secret: bool, actor: str, ip: str = ""
) -> str | None:
    """Set the client's webhook URL (None keeps it, "" removes it and its secret) and, with
    `rotate_secret` (or when a URL is set and there is no secret yet), make a new secret.
    Returns the new secret (shown once) or None. Raises InvalidWebhookUrl (not https)."""
    fields: list[str] = []
    if url is not None:
        url = url.strip()
        if url:
            try:
                URLValidator(schemes=["https"])(url)
            except ValidationError as error:
                raise InvalidWebhookUrl(url) from error
            if len(url) > 500:
                raise InvalidWebhookUrl(url)
        client.webhook_url = url
        fields.append("webhook_url")
        if not url:
            client.webhook_secret_encrypted = None
            fields.append("webhook_secret_encrypted")
    secret: str | None = None
    needs_secret = bool(client.webhook_url) and client.webhook_secret_encrypted is None
    if client.webhook_url and (rotate_secret or needs_secret):
        secret = get_randomness().token_bytes(SECRET_BYTES).hex()
        client.webhook_secret_encrypted = encrypt_secret(secret.encode())
        fields.append("webhook_secret_encrypted")
    if fields:
        client.save(update_fields=sorted(set(fields)))
        audit.record(
            audit.CLIENT_WEBHOOK_CHANGED,
            actor=actor,
            client_id=client.client_id,
            ip=ip,
            detail={"url": client.webhook_url, "new_signing_key": secret is not None},
        )
    return secret


def webhook_secret(client: Client) -> str | None:
    raw = client.webhook_secret_encrypted
    if not client.webhook_url or raw is None:
        return None
    return decrypt_secret(bytes(raw)).decode()


def sign(secret: str, timestamp: int, body: bytes) -> str:
    """The `X-Sandcorp-Signature` value for `body` sent at `timestamp` (unix seconds)."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


def enqueue_user_deleted(sub: str, occurred_at: datetime, clients: list[Client]) -> int:
    """Queue `user.deleted` for `sub` to each client that has a webhook. Call it inside the
    withdrawal's transaction. Returns how many were queued."""
    now = get_clock().now()
    queued = 0
    for client in clients:
        if not client.webhook_url or client.webhook_secret_encrypted is None:
            continue
        event_id = new_ulid()
        body = json.dumps(
            {
                "id": event_id,
                "type": USER_DELETED,
                "sub": sub,
                "occurred_at": occurred_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            separators=(",", ":"),
        )
        WebhookDelivery.objects.create(
            event_id=event_id,
            client=client,
            event_type=USER_DELETED,
            body=body,
            created_at=now,
            next_attempt_at=now,
        )
        queued += 1
    return queued


@dataclass
class DeliveryReport:
    delivered: int = 0
    retrying: int = 0
    gave_up: int = 0


def deliver_due(*, limit: int = 100) -> DeliveryReport:
    """Send every queued delivery whose time has come (at most `limit`)."""
    report = DeliveryReport()
    now = get_clock().now()
    due = list(
        WebhookDelivery.objects.filter(
            delivered_at__isnull=True, gave_up_at__isnull=True, next_attempt_at__lte=now
        )
        .order_by("next_attempt_at", "pk")
        .values_list("pk", "next_attempt_at")[:limit]
    )
    for pk, next_attempt_at in due:
        # Claim it (another sender running at the same time skips it), then send unlocked.
        claimed = WebhookDelivery.objects.filter(
            pk=pk,
            next_attempt_at=next_attempt_at,
            delivered_at__isnull=True,
            gave_up_at__isnull=True,
        ).update(next_attempt_at=now + CLAIM_LEASE, attempts=F("attempts") + 1, last_attempt_at=now)
        if not claimed:
            continue
        delivery = WebhookDelivery.objects.select_related("client").get(pk=pk)
        error = _send(delivery)
        with transaction.atomic():
            if error is None:
                delivery.delivered_at = now
                delivery.next_attempt_at = None
                delivery.last_error = ""
                report.delivered += 1
            elif delivery.attempts >= MAX_ATTEMPTS:
                delivery.gave_up_at = now
                delivery.next_attempt_at = None
                delivery.last_error = error
                report.gave_up += 1
            else:
                delivery.next_attempt_at = now + RETRY_DELAYS[delivery.attempts - 1]
                delivery.last_error = error
                report.retrying += 1
            delivery.save(
                update_fields=["delivered_at", "gave_up_at", "next_attempt_at", "last_error"]
            )
    return report


def _send(delivery: WebhookDelivery) -> str | None:
    """One attempt; None when the client answered 2xx, else why not."""
    secret = webhook_secret(delivery.client)
    if secret is None:
        return "no webhook configured"
    body = delivery.body.encode()
    timestamp = int(get_clock().now().timestamp())
    headers = {
        SIGNATURE_HEADER: sign(secret, timestamp, body),
        EVENT_HEADER: delivery.event_type,
        DELIVERY_HEADER: delivery.event_id,
        "User-Agent": "sandcorp-auth-webhook/1",
    }
    try:
        status = get_webhook_http().post(delivery.client.webhook_url, body, headers=headers)
    except FetchError as error:
        return f"fetch: {error}"[:200]
    if 200 <= status < 300:
        return None
    return f"status {status}"
