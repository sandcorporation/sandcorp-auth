from argparse import ArgumentParser

from django.core.management.base import BaseCommand, CommandError

from services.signing import (
    ActiveSigningKeyExists,
    create_signing_key,
    list_signing_keys,
    rotate_signing_key,
)


class Command(BaseCommand):
    help = "Manage token signing keys: create (first key), rotate, list."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("action", choices=["create", "rotate", "list"])

    def handle(self, *args: object, **options: str) -> None:
        action = options["action"]
        if action == "create":
            try:
                key = create_signing_key()
            except ActiveSigningKeyExists:
                raise CommandError(
                    "an active signing key already exists; use `signing_keys rotate`",
                    returncode=1,
                ) from None
            self.stdout.write(f"created active key {key.kid}")
        elif action == "rotate":
            key = rotate_signing_key()
            self.stdout.write(f"rotated: new active key {key.kid}")
        else:
            self._list()

    def _list(self) -> None:
        self.stdout.write(f"{'kid':<24} {'state':<8} {'created_at':<26} retired_at")
        for key in list_signing_keys():
            state = "active" if key.active else "retired"
            retired = key.retired_at.isoformat() if key.retired_at else "-"
            self.stdout.write(
                f"{key.kid:<24} {state:<8} {key.created_at.isoformat():<26} {retired}"
            )
