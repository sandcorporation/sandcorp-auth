from argparse import ArgumentParser

from django.core.management.base import BaseCommand

from oauth.models import WebhookDelivery
from services.webhooks import deliver_due


class Command(BaseCommand):
    help = (
        "웹훅 대기열(ADR 0004): deliver — 보낼 때가 된 전송을 보낸다(5분마다 돌린다). "
        "list — 끝나지 않은 전송과 포기한 전송."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        actions = parser.add_subparsers(dest="action", required=True)
        deliver = actions.add_parser("deliver", help="보낼 때가 된 전송을 보낸다")
        deliver.add_argument("--limit", type=int, default=100)
        actions.add_parser("list", help="대기 중이거나 포기한 전송 목록")

    def handle(self, *args: object, **options: object) -> None:
        if options["action"] == "deliver":
            limit = options["limit"]
            assert isinstance(limit, int)
            report = deliver_due(limit=limit)
            self.stdout.write(
                f"delivered={report.delivered} retrying={report.retrying} gave_up={report.gave_up}"
            )
            return
        for delivery in (
            WebhookDelivery.objects.filter(delivered_at__isnull=True)
            .select_related("client")
            .order_by("created_at", "pk")
        ):
            state = (
                "gave_up"
                if delivery.gave_up_at
                else f"next={delivery.next_attempt_at:%Y-%m-%dT%H:%M:%SZ}"
            )
            self.stdout.write(
                f"{delivery.event_id}\t{delivery.event_type}\t{delivery.client.client_id}\t"
                f"attempts={delivery.attempts}\t{state}\t{delivery.last_error}"
            )
