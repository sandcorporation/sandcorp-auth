from argparse import ArgumentParser

from django.core.management.base import BaseCommand, CommandError

from services.merge import MergeRefused, merge_member_into_owner
from services.withdrawal import purge_withdrawn


class Command(BaseCommand):
    help = (
        "일반 사용자 관리: purge — 탈퇴 30일이 지난 계정의 개인정보(이메일·이름·외부 신원·약관 "
        "동의·앱 동의)를 지우고 sub는 묘비로 남긴다. 1년 지난 감사 기록, 30일 지난 끝난 웹훅 "
        "전송, 하루 넘게 쉰 요청 제한 카운터도 지운다(ADR 0004). 하루 한 번 돌린다. "
        "merge — 일반 사용자 계정을 대표 계정에 합친다(#100): 소셜 로그인·앱 동의를 옮기고 "
        "토큰·세션을 끊고 user.merged 웹훅을 보낸 뒤 계정을 지운다."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        actions = parser.add_subparsers(dest="action", required=True)
        purge = actions.add_parser("purge", help="보유 기간이 끝난 개인정보·기록을 지운다")
        purge.add_argument("--dry-run", action="store_true", help="지우지 않고 대상만 센다")
        merge = actions.add_parser("merge", help="일반 사용자 계정을 대표 계정에 합친다")
        merge.add_argument("--from", dest="source", required=True, help="회원 username(m_…)")
        merge.add_argument("--into", dest="target", required=True, help="대표 username")
        merge.add_argument("--dry-run", action="store_true", help="바꾸지 않고 개수만 센다")

    def handle(self, *args: object, **options: object) -> None:
        if options["action"] == "merge":
            self._merge(str(options["source"]), str(options["target"]), bool(options["dry_run"]))
            return
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

    def _merge(self, source: str, target: str, dry_run: bool) -> None:
        try:
            report = merge_member_into_owner(source, target, dry_run=dry_run)
        except MergeRefused as error:
            raise CommandError(f"합치지 않았습니다: {error}") from error
        head = "옮길 것(바꾸지 않음)" if dry_run else "합쳤습니다"
        self.stdout.write(f"{report.from_sub} → {report.to_sub} {head}")
        self.stdout.write(f"소셜 로그인 {len(report.identities)}개 {' '.join(report.identities)}")
        self.stdout.write(f"앱 동의 옮김 {report.consents_moved}건")
        self.stdout.write(f"앱 동의 합침(대표에 이미 있음) {report.consents_combined}건")
        self.stdout.write(f"리프레시 토큰 패밀리 폐기 {report.families_revoked}건")
        self.stdout.write(f"세션 삭제 {report.sessions_deleted}건")
        self.stdout.write(f"약관 동의 기록(감사 기록에 남김) {report.terms_agreements}건")
        self.stdout.write(f"user.merged 웹훅 {report.webhooks}건")
