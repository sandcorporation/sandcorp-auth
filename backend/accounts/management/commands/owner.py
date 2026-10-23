import getpass
import sys
from argparse import ArgumentParser

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from services.owner import (
    NoOwner,
    OwnerExists,
    create_owner,
    reset_owner_totp,
    set_owner_email,
    set_owner_name,
    set_owner_password,
)

DEFAULT_USERNAME = "farrar142"


class Command(BaseCommand):
    help = (
        "대표 계정 관리: create(처음 한 번), set-password, reset-totp, "
        "set-email --email, set-name --name (OIDC 로그인 정보)."
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "action", choices=["create", "set-password", "reset-totp", "set-email", "set-name"]
        )
        parser.add_argument("--username", default=DEFAULT_USERNAME)
        parser.add_argument(
            "--password", help="생략하면 터미널에서 묻거나 표준 입력의 첫 줄을 읽는다"
        )
        parser.add_argument("--email", help="set-email: 대표 이메일(빈 값이면 지운다)")
        parser.add_argument("--name", help="set-name: 대표 표시 이름(빈 값이면 지운다)")

    def _password(self, given: str | None) -> str:
        if given is not None:
            return given
        if not sys.stdin.isatty():
            return sys.stdin.readline().rstrip("\n")
        first = getpass.getpass("비밀번호: ")
        if getpass.getpass("비밀번호 확인: ") != first:
            raise CommandError("두 비밀번호가 다릅니다", returncode=1)
        return first

    def handle(self, *args: object, **options: str | None) -> None:
        action = options["action"]
        try:
            if action == "create":
                username = options["username"] or DEFAULT_USERNAME
                owner = create_owner(username, self._password(options["password"]))
                self.stdout.write(
                    f"대표 계정 '{owner.username}'을(를) 만들었습니다.\n"
                    f"이 이름이 액세스 토큰의 sub입니다 — 사이트의 AUTH_OWNER_SUB에 "
                    f"'{owner.username}'을(를) 넣으세요.\n"
                    "첫 로그인 때 인증 앱(TOTP) 등록을 거칩니다."
                )
            elif action == "set-password":
                owner = set_owner_password(self._password(options["password"]))
                self.stdout.write(
                    f"'{owner.username}'의 비밀번호를 바꿨습니다. 기존 세션은 끝납니다."
                )
            elif action == "set-email":
                if options["email"] is None:
                    raise CommandError("--email이 필요합니다", returncode=1)
                owner = set_owner_email(options["email"])
                self.stdout.write(f"'{owner.username}'의 이메일: {owner.email or '(없음)'}")
            elif action == "set-name":
                if options["name"] is None:
                    raise CommandError("--name이 필요합니다", returncode=1)
                owner = set_owner_name(options["name"])
                self.stdout.write(f"'{owner.username}'의 이름: {owner.first_name or '(없음)'}")
            else:
                owner = reset_owner_totp()
                self.stdout.write(
                    f"'{owner.username}'의 TOTP를 지웠습니다. 다음 로그인 때 다시 등록합니다."
                )
        except OwnerExists:
            raise CommandError(
                "대표 계정이 이미 있습니다(계정은 하나뿐). 비밀번호는 set-password로 바꾸세요.",
                returncode=1,
            ) from None
        except NoOwner:
            raise CommandError("대표 계정이 없습니다. 먼저 owner create.", returncode=1) from None
        except ValidationError as error:
            raise CommandError(" ".join(error.messages), returncode=1) from None
