"""The ninja API. Endpoints stay thin: they validate input and call the service layer."""

from datetime import datetime

from django.db import connection
from django.db.utils import DatabaseError
from django.http import HttpRequest
from ninja import NinjaAPI, Schema, Status

from adapters.clock import get_clock

api = NinjaAPI(title="Sandcorp auth API", docs_url=None)


class Health(Schema):
    status: str
    db: str
    time: datetime


@api.get("/health", response={200: Health, 503: Health}, auth=None)
def health(request: HttpRequest) -> Status[Health]:
    """Liveness: a real Postgres round trip plus the server time; the deploy waits on this."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except DatabaseError:
        return Status(503, Health(status="error", db="unavailable", time=get_clock().now()))
    return Status(200, Health(status="ok", db="ok", time=get_clock().now()))
