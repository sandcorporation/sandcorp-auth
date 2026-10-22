"""HTTP adapter: the one place services fetch a document from another host (CIMD).

Services call `get_http_client()`; tests swap in a fake with `set_http_client()`
(tests/conftest.py `fake_http`). Host name resolution lives here too so tests never touch DNS.
The real client never follows redirects and reads at most `max_bytes + 1` bytes, so the caller
can tell "too large" from "exactly the limit".
"""

import socket
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


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

    def fetch_json(self, url: str, *, max_bytes: int, timeout: float) -> FetchedDocument: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None  # urllib then raises HTTPError with the 3xx status


class UrllibHttpClient:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect)

    def resolve(self, host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError) as error:
            raise FetchError(f"cannot resolve {host}") from error
        return sorted({str(info[4][0]) for info in infos})

    def fetch_json(self, url: str, *, max_bytes: int, timeout: float) -> FetchedDocument:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with self._opener.open(request, timeout=timeout) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                return FetchedDocument(response.status, headers, response.read(max_bytes + 1))
        except urllib.error.HTTPError as error:
            headers = {k.lower(): v for k, v in error.headers.items()}
            return FetchedDocument(error.code, headers, b"")
        except (OSError, ValueError) as error:  # URLError, timeout, TLS errors
            raise FetchError(str(error)) from error


_http_client: HttpClient = UrllibHttpClient()


def get_http_client() -> HttpClient:
    return _http_client


def set_http_client(client: HttpClient) -> HttpClient:
    """Install `client` and return the previous one so callers can restore it."""
    global _http_client
    previous, _http_client = _http_client, client
    return previous
