"""HTTP adapter: the one place services fetch a document from another host (CIMD).

Services call `get_http_client()`; tests swap in a fake with `set_http_client()`
(tests/conftest.py `fake_http`). Host name resolution lives here too so tests never touch DNS.
The real client connects only to the address the caller checked (no second DNS lookup), never
follows redirects and reads at most `max_bytes + 1` bytes, so the caller can tell "too large"
from "exactly the limit".
"""

import http.client
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit


@dataclass(frozen=True)
class FetchedDocument:
    status: int
    # Lower-cased header names.
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""


class FetchError(Exception):
    """The document could not be fetched at all (connection, timeout, TLS, bad URL)."""


class HttpClient(Protocol):
    def resolve(self, host: str) -> list[str]:
        """Every IP address `host` resolves to. Raises FetchError when it does not resolve."""
        ...

    def fetch_json(
        self, url: str, *, address: str, max_bytes: int, timeout: float
    ) -> FetchedDocument:
        """GET the https `url` over a connection to `address` (an IP the caller already
        checked), never resolving the host name again. TLS SNI, certificate checking and the
        `Host` header still use the URL's host name."""
        ...


class TlsWrapper(Protocol):
    """The part of `ssl.SSLContext` the client uses (tests pass a recording stand-in)."""

    def wrap_socket(self, sock: socket.socket, *, server_hostname: str) -> socket.socket: ...


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection whose TCP connect goes to a fixed address instead of resolving
    `host`; `host` is still what TLS (SNI, hostname check) and the `Host` header see."""

    def __init__(
        self, host: str, *, address: str, port: int, timeout: float, tls: TlsWrapper
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address
        self._tls = tls

    def connect(self) -> None:
        # IPv6 addresses go in bare (no brackets): create_connection takes a sockaddr host.
        sock = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class PinnedHttpsClient:
    """The real client: `getaddrinfo` for `resolve`, and `http.client` pinned to the checked
    address for `fetch_json`, so a DNS answer that changes between check and connect (DNS
    rebinding) cannot steer the request elsewhere. `http.client` never follows redirects: a 3xx
    comes back as its status with an empty body."""

    def __init__(self, *, port: int = 443, tls: TlsWrapper | None = None) -> None:
        self.port = port
        self.tls: TlsWrapper = tls if tls is not None else ssl.create_default_context()

    def resolve(self, host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError) as error:
            raise FetchError(f"cannot resolve {host}") from error
        return sorted({str(info[4][0]) for info in infos})

    def fetch_json(
        self, url: str, *, address: str, max_bytes: int, timeout: float
    ) -> FetchedDocument:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise FetchError(f"not an https URL: {url}")
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        connection = _PinnedHTTPSConnection(
            parts.hostname, address=address, port=self.port, timeout=timeout, tls=self.tls
        )
        try:
            connection.request("GET", target, headers={"Accept": "application/json"})
            response = connection.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            if not 200 <= response.status < 300:
                return FetchedDocument(response.status, headers, b"")
            return FetchedDocument(response.status, headers, response.read(max_bytes + 1))
        except (OSError, http.client.HTTPException, ValueError) as error:  # timeout, TLS too
            raise FetchError(str(error) or type(error).__name__) from error
        finally:
            connection.close()


_http_client: HttpClient = PinnedHttpsClient()


def get_http_client() -> HttpClient:
    return _http_client


def set_http_client(client: HttpClient) -> HttpClient:
    """Install `client` and return the previous one so callers can restore it."""
    global _http_client
    previous, _http_client = _http_client, client
    return previous
