"""Bounded JSON transport with explicit destinations and no credential redirects."""
import urllib.request
from typing import Any
from urllib.parse import urlsplit
from intentlock.schema import canonical, parse_json

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward an authorization header to a redirected destination."""
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        """Reject redirects rather than following potentially different origins."""
        raise ValueError('API redirects are forbidden')


def fetch_json(url: str, token: str, payload: dict[str, Any] | None = None) -> Any:
    """Fetch bounded strict JSON over verified HTTPS or loopback-only HTTP."""
    target = urlsplit(url)
    if target.username or target.password or target.fragment or not target.hostname:
        raise ValueError('invalid API destination')
    if target.scheme != 'https' and not (target.scheme == 'http' and target.hostname in {'localhost','127.0.0.1','::1'}):
        raise ValueError('HTTPS required outside loopback')
    request = urllib.request.Request(url, data=None if payload is None else canonical(payload), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('API response too large')
    return parse_json(raw)
