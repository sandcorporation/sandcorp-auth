"""`manage.py glitchtip_test` — GlitchTip 연동 확인용 시험 오류 한 건을 보낸다(#78).

`GlitchTipOnboardingTest("연동 시험 auth <날짜>")`를 던져 잡고 GlitchTip으로 보낸 뒤 이벤트 id를
찍는다. 자동화 precheck가 이 예외 이름을 보고 `[운영] auth [시험] …`으로 대장에게 보고한다.
DSN이 없으면(dev·시험) 보낼 곳이 없으니 종료 코드 1.
"""

from django.core.management.base import BaseCommand, CommandError

from adapters.clock import get_clock
from core.observability import GlitchTipOnboardingTest


class Command(BaseCommand):
    help = "Send one GlitchTipOnboardingTest error to GlitchTip (needs SENTRY_DSN)."

    def handle(self, *args: object, **options: object) -> None:
        import sentry_sdk

        if not sentry_sdk.get_client().is_active():
            raise CommandError("SENTRY_DSN이 없어 GlitchTip SDK가 꺼져 있다", returncode=1)
        today = get_clock().now().date().isoformat()
        try:
            raise GlitchTipOnboardingTest(f"연동 시험 auth {today}")
        except GlitchTipOnboardingTest as exc:
            event_id = sentry_sdk.capture_exception(exc)
        sentry_sdk.flush(timeout=10)
        if event_id is None:
            raise CommandError(
                "이벤트를 보내지 못했다(before_send가 버렸거나 SDK 오류)", returncode=1
            )
        self.stdout.write(f"sent GlitchTipOnboardingTest event {event_id}")
