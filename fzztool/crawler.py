"""Opt-in, bounded same-origin crawling with explicit authentication.

Only for targets the operator owns or is explicitly authorized to test.
Disabled by default: nothing in FZZ crawls or authenticates unless the
operator passes --crawl / --auth-header / --auth-cookie explicitly.

Hard limits (never raised by flags):
- same origin only (scheme + host + port must match the target);
- max depth 2, max 30 URLs;
- auth headers are sent ONLY to the target origin. Redirects are followed
  manually and only while they stay in-origin, so a redirect to another
  host never receives the credentials;
- the token value is never included in results, reports or logs: only
  ``auth_used`` (bool) is recorded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Any

import requests

MAX_CRAWL_DEPTH = 2
MAX_CRAWL_URLS = 30
MAX_CRAWL_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 512_000
MAX_REDIRECTS = 5
MAX_PARAMETER_CANDIDATES = 32

_USER_AGENT = "FZZ-crawler/1.0 (authorized security testing)"


class CrawlError(ValueError):
    """Raised when the crawl target or the auth input is invalid."""


def _reject_control(value: str, what: str) -> None:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CrawlError(f"{what} no puede contener caracteres de control ni saltos de línea")


def parse_auth_header(value: str) -> tuple[str, str]:
    """Validate 'Name: token' and return (name, token) without logging it."""
    _reject_control(value, "La cabecera de autenticación")
    if ":" not in value:
        raise CrawlError("La cabecera de autenticación debe tener formato 'Nombre: valor'")
    name, token = value.split(":", 1)
    name, token = name.strip(), token.strip()
    if not name or not token:
        raise CrawlError("La cabecera de autenticación necesita nombre y valor no vacíos")
    if any(char.isspace() for char in name):
        raise CrawlError("El nombre de la cabecera de autenticación no puede contener espacios")
    return name, token


def parse_auth_cookie(value: str) -> str:
    """Validate a Cookie header value (e.g. 'session=abc')."""
    _reject_control(value, "La cookie de autenticación")
    value = value.strip()
    if not value or "=" not in value:
        raise CrawlError("La cookie de autenticación debe tener formato 'nombre=valor'")
    return value


def build_auth_headers(
    auth_header: str | None = None,
    auth_cookie: str | None = None,
) -> dict[str, str]:
    """Build the auth headers from explicit operator input. Never logged."""
    headers: dict[str, str] = {}
    if auth_header is not None:
        name, token = parse_auth_header(auth_header)
        headers[name] = token
    if auth_cookie is not None:
        headers["Cookie"] = parse_auth_cookie(auth_cookie)
    return headers


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port)


def _same_origin(url: str, base_url: str) -> bool:
    return _origin(url) == _origin(base_url)


def _normalize(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)


@dataclass(frozen=True)
class CrawlConfig:
    base_url: str
    max_depth: int = MAX_CRAWL_DEPTH
    max_urls: int = MAX_CRAWL_URLS
    timeout: float = 10.0
    auth_header: str | None = None
    auth_cookie: str | None = None
    max_response_bytes: int = MAX_RESPONSE_BYTES

    def validate(self) -> str:
        url = self.base_url.strip()
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise CrawlError("El target debe usar http:// o https://")
        if not parsed.hostname:
            raise CrawlError("El target debe incluir un hostname válido")
        if parsed.username or parsed.password:
            raise CrawlError("No se permiten credenciales embebidas en la URL del target")
        try:
            port = parsed.port
        except ValueError as exc:
            raise CrawlError("El puerto del target no es válido") from exc
        if port is not None and not 1 <= port <= 65535:
            raise CrawlError("El puerto del target debe estar entre 1 y 65535")
        if not 0 <= self.max_depth <= MAX_CRAWL_DEPTH:
            raise CrawlError(f"La profundidad de crawling debe estar entre 0 y {MAX_CRAWL_DEPTH}")
        if not 1 <= self.max_urls <= MAX_CRAWL_URLS:
            raise CrawlError(f"El límite de URLs debe estar entre 1 y {MAX_CRAWL_URLS}")
        if not 0.1 <= self.timeout <= MAX_CRAWL_TIMEOUT:
            raise CrawlError(f"El timeout de crawling debe estar entre 0.1 y {MAX_CRAWL_TIMEOUT}")
        if not 1_024 <= self.max_response_bytes <= MAX_RESPONSE_BYTES:
            raise CrawlError(f"El límite de respuesta debe estar entre 1024 y {MAX_RESPONSE_BYTES} bytes")
        build_auth_headers(self.auth_header, self.auth_cookie)
        return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))

    def headers(self) -> dict[str, str]:
        return build_auth_headers(self.auth_header, self.auth_cookie)

    def headers_for(self, url: str) -> dict[str, str]:
        """Auth headers only when the URL is the target origin, else {}."""
        return self.headers() if _same_origin(url, self.base_url) else {}


@dataclass
class CrawlResult:
    base_url: str
    urls: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    skipped_off_scope: int = 0
    auth_used: bool = False
    max_depth: int = MAX_CRAWL_DEPTH
    max_urls: int = MAX_CRAWL_URLS

    def to_dict(self) -> dict[str, Any]:
        # Deliberately no token, no header values, no cookies.
        return {
            "base_url": self.base_url,
            "urls": list(self.urls),
            "parameters": list(self.parameters),
            "visited": len(self.urls),
            "skipped_off_scope": self.skipped_off_scope,
            "auth_used": self.auth_used,
            "max_depth": self.max_depth,
            "max_urls": self.max_urls,
        }


def _fetch(
    url: str,
    headers: dict[str, str],
    client: requests.Session,
    timeout: float,
) -> requests.Response | None:
    """GET with manual, in-origin-only redirect handling (max 5 hops).

    Returns the last response received from the target origin, including
    a 3xx whose Location points off-origin (the caller records the
    requested URL but never follows it). None only on network error or
    redirect-loop exhaustion, so no request is ever sent off-origin.
    """
    current = url
    response: requests.Response | None = None
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = client.get(
                current,
                timeout=timeout,
                allow_redirects=False,
                headers={**headers, "User-Agent": _USER_AGENT},
            )
        except requests.RequestException:
            return None
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        if not location:
            return response
        nxt = _normalize(urljoin(current, location))
        if not _same_origin(nxt, url):
            return response  # stop here: do not send auth off-origin
        current = nxt
    return response


def crawl_target(
    config: CrawlConfig,
    *,
    session: requests.Session | None = None,
) -> CrawlResult:
    """Breadth-first crawl, same origin only, bounded by depth and URL cap."""
    from .recon import _parameter_candidates

    base_url = config.validate()
    headers = config.headers()
    client = session or requests.Session()
    result = CrawlResult(
        base_url=base_url,
        auth_used=bool(headers),
        max_depth=config.max_depth,
        max_urls=config.max_urls,
    )
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    while queue and len(result.urls) < config.max_urls:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        response = _fetch(url, config.headers_for(url), client, config.timeout)
        if response is None:
            continue
        result.urls.append(url)
        if not _same_origin(str(response.url), base_url):
            continue  # final URL ended up off-origin: do not parse it
        if "text/html" not in (response.headers.get("Content-Type") or ""):
            continue
        body = response.content[: config.max_response_bytes].decode(
            response.encoding or "utf-8", errors="replace"
        )
        # Parameters are collected from every visited page, including
        # pages at max depth; only following their links is limited.
        for name in _parameter_candidates(str(response.url), body):
            if name not in result.parameters:
                result.parameters.append(name)
            if len(result.parameters) >= MAX_PARAMETER_CANDIDATES:
                break
        if depth >= config.max_depth:
            continue
        parser = _LinkParser()
        try:
            parser.feed(body)
        except Exception:
            continue
        for href in parser.links:
            target = _normalize(urljoin(str(response.url), href))
            parsed = urlparse(target)
            if parsed.scheme.lower() not in {"http", "https"}:
                continue
            if not _same_origin(target, base_url):
                result.skipped_off_scope += 1
                continue
            if target not in seen and all(target != queued for queued, _ in queue):
                queue.append((target, depth + 1))
    return result


__all__ = [
    "CrawlConfig",
    "CrawlError",
    "CrawlResult",
    "build_auth_headers",
    "crawl_target",
    "parse_auth_cookie",
    "parse_auth_header",
]
