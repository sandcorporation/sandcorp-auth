"""The real HTTP adapter (`PinnedHttpsClient`) against a local plain-HTTP server: TLS is swapped
for a pass-through wrapper that records the SNI name, so the test sees the connection is
opened to the pinned address while SNI and `Host` stay the original host name, and the name is
never resolved again. Certificate checking is pinned by asserting the default TLS context."""

import socket
import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from adapters.http import FetchError, PinnedHttpsClient

HOST = "app.example"  # never resolves: reaching the server proves the address was pinned


class PassThroughTls:
    """Stands in for `ssl.SSLContext`: no TLS, but records the SNI name it was given."""

    def __init__(self) -> None:
        self.server_hostnames: list[str | None] = []

    def wrap_socket(self, sock: socket.socket, *, server_hostname: str | None) -> socket.socket:
        self.server_hostnames.append(server_hostname)
        return sock


class Handler(BaseHTTPRequestHandler):
    hosts: list[str | None] = []

    def do_GET(self) -> None:
        Handler.hosts.append(self.headers.get("Host"))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/client.json")
            self.end_headers()
            return
        body = b"x" * 5000 if self.path == "/big" else b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "max-age=60")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def local_server() -> Iterator[int]:
    Handler.hosts = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every host name passed to `socket.getaddrinfo` while the test runs."""
    seen: list[str] = []
    real = socket.getaddrinfo

    def recording(host: str, *args: object, **kwargs: object) -> object:
        seen.append(host)
        return real(host, *args, **kwargs)  # type: ignore[arg-type]  # pass-through wrapper

    monkeypatch.setattr(socket, "getaddrinfo", recording)
    return seen


def test_connects_to_the_pinned_address_with_original_sni_and_host(
    local_server: int, lookups: list[str]
) -> None:
    tls = PassThroughTls()
    client = PinnedHttpsClient(port=local_server, tls=tls)
    fetched = client.fetch_json(
        f"https://{HOST}/client.json?v=1", address="127.0.0.1", max_bytes=100, timeout=5
    )
    assert fetched.status == 200
    assert fetched.body == b'{"ok": true}'
    assert fetched.headers["content-type"] == "application/json"
    assert fetched.headers["cache-control"] == "max-age=60"
    assert tls.server_hostnames == [HOST]
    assert Handler.hosts == [f"{HOST}:{local_server}"]  # port shown only when not 443
    assert HOST not in lookups


def test_connect_uses_only_the_given_address(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int]] = []

    def refuse(address: tuple[str, int], *args: object, **kwargs: object) -> socket.socket:
        calls.append(address)
        raise ConnectionRefusedError

    monkeypatch.setattr(socket, "create_connection", refuse)
    client = PinnedHttpsClient(tls=PassThroughTls())
    with pytest.raises(FetchError):
        client.fetch_json(
            f"https://{HOST}/client.json", address="2001:db8::1", max_bytes=100, timeout=5
        )
    assert calls == [("2001:db8::1", 443)]


def test_redirects_are_not_followed(local_server: int) -> None:
    client = PinnedHttpsClient(port=local_server, tls=PassThroughTls())
    fetched = client.fetch_json(
        f"https://{HOST}/redirect", address="127.0.0.1", max_bytes=100, timeout=5
    )
    assert fetched.status == 302
    assert fetched.body == b""
    assert Handler.hosts == [f"{HOST}:{local_server}"]  # port shown only when not 443


def test_reads_at_most_one_byte_over_the_limit(local_server: int) -> None:
    client = PinnedHttpsClient(port=local_server, tls=PassThroughTls())
    fetched = client.fetch_json(
        f"https://{HOST}/big", address="127.0.0.1", max_bytes=100, timeout=5
    )
    assert len(fetched.body) == 101


def test_non_https_urls_are_refused() -> None:
    client = PinnedHttpsClient(tls=PassThroughTls())
    with pytest.raises(FetchError):
        client.fetch_json(f"http://{HOST}/client.json", address="127.0.0.1", max_bytes=1, timeout=1)


def test_default_tls_checks_the_certificate_against_the_host_name() -> None:
    tls = PinnedHttpsClient().tls
    assert isinstance(tls, ssl.SSLContext)
    assert tls.check_hostname is True
    assert tls.verify_mode == ssl.CERT_REQUIRED
