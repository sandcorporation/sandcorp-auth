from argparse import ArgumentParser
from datetime import date

from django.core.management.base import BaseCommand, CommandError

from accounts.models import TermsDocument
from services.terms import TermsVersionExists, current_documents, register_document


class Command(BaseCommand):
    help = (
        "약관 문서 버전(#37): add --kind terms|privacy --doc-version <이름> --effective YYYY-MM-DD "
        "--url <공개 주소>, list. 종류마다 시행 중인 버전이 하나라도 없으면 member 가입이 막힌다."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("action", choices=["add", "list"])
        parser.add_argument("--kind", choices=[kind.value for kind in TermsDocument.Kind])
        parser.add_argument("--doc-version")
        parser.add_argument("--effective", help="시행일 YYYY-MM-DD")
        parser.add_argument("--url", help="privacy-and-terms 공개 페이지 주소(https)")

    def handle(self, *args: object, **options: str | None) -> None:
        if options["action"] == "list":
            current = set(current_documents().values_list("id", flat=True))
            for d in TermsDocument.objects.order_by("kind", "-effective_date", "-id"):
                mark = "*" if d.pk in current else " "
                self.stdout.write(f"{mark} {d.kind}\t{d.version}\t{d.effective_date}\t{d.url}")
            return
        kind, version, effective, url = (
            options["kind"],
            options["doc_version"],
            options["effective"],
            options["url"],
        )
        if not (kind and version and effective and url):
            raise CommandError("add에는 --kind, --doc-version, --effective, --url이 모두 필요하다")
        if not url.startswith("https://"):
            raise CommandError("--url은 https 주소여야 한다")
        try:
            effective_date = date.fromisoformat(effective)
        except ValueError:
            raise CommandError("--effective는 YYYY-MM-DD") from None
        try:
            document = register_document(
                kind=kind,
                version=version,
                effective_date=effective_date,
                url=url,
                actor="manage.py terms",
            )
        except TermsVersionExists:
            raise CommandError(f"{kind} {version}은 이미 등록돼 있다") from None
        self.stdout.write(f"등록: {document} ({document.effective_date} 시행)")
