from argparse import ArgumentParser

from django.core.management.base import BaseCommand

from services.withdrawal import purge_withdrawn


class Command(BaseCommand):
    help = (
        "일반 사용자 관리: purge — 탈퇴 30일이 지난 계정의 개인정보(이메일·이름·외부 신원·약관 "
        "동의·앱 동의)를 지우고 sub는 묘비로 남긴다. 1년 지난 감사 기록, 30일 지난 끝난 웹훅 "
        "전송, 하루 넘게 쉰 요청 제한 카운터도 지운다(ADR 0004). 하루 한 번 돌린다."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        actions = parser.add_subparsers(dest="action", required=True)
        purge = actions.add_parser("purge", help="보유 기간이 끝난 개인정보·기록을 지운다")
        purge.add_argument("--dry-run", action="store_true", help="지우지 않고 대상만 센다")

    def handle(self, *args: object, **options: object) -> None:
        dry_run = bool(options["dry_run"])
        report = purge_withdrawn(dry_run=dry_run)
        verb = "지울 대상" if dry_run else "지웠습니다"
        self.stdout.write(f"탈퇴 계정 {len(report.members)}개 {verb}")
        for sub in report.members:
            self.stdout.write(f"  {sub}")
        self.stdout.write(f"감사 기록(1년 지남) {report.audit_events}건")
        self.stdout.write(f"끝난 웹훅 전송(30일 지남) {report.webhook_deliveries}건")
        if not dry_run:
            self.stdout.write(f"쉬는 요청 제한 카운터 {report.throttle_counters}건")
