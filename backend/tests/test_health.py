import pytest
from django.db import connection
from django.db.utils import OperationalError
from django.test import Client

from tests.conftest import FrozenClock


@pytest.mark.django_db
def test_health_reports_database_reachable_and_server_time(
    client: Client, frozen_clock: FrozenClock
) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "db": "ok", "time": "2026-01-01T00:00:00Z"}

    frozen_clock.advance(90)

    assert client.get("/api/health").json()["time"] == "2026-01-01T00:01:30Z"


@pytest.mark.django_db
def test_health_reports_unavailable_when_database_is_down(
    client: Client, monkeypatch: pytest.MonkeyPatch, frozen_clock: FrozenClock
) -> None:
    def refuse() -> None:
        raise OperationalError("connection refused")

    monkeypatch.setattr(connection, "cursor", refuse)

    response = client.get("/api/health")

    assert response.status_code == 503
    assert response.json() == {
        "status": "error",
        "db": "unavailable",
        "time": "2026-01-01T00:00:00Z",
    }


@pytest.mark.django_db
def test_production_security_headers(client: Client, frozen_clock: FrozenClock) -> None:
    # Plain http (the in-container health check) is served, not redirected: NPMplus owns TLS.
    plain = client.get("/api/health")
    assert plain.status_code == 200
    assert "Strict-Transport-Security" not in plain.headers

    behind_proxy = client.get("/api/health", headers={"X-Forwarded-Proto": "https"})

    assert behind_proxy.status_code == 200
    assert behind_proxy.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert behind_proxy.headers["X-Frame-Options"] == "DENY"
    assert behind_proxy.headers["Referrer-Policy"] == "same-origin"
    assert behind_proxy.headers["X-Content-Type-Options"] == "nosniff"
