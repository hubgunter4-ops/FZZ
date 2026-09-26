"""Safe, bounded HTTP reconnaissance for an explicitly supplied target."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from html import unescape
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse

import requests

MAX_RECON_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 512_000
MAX_PARAMETER_CANDIDATES = 32
_BASELINE_MARKERS = ("49", "root:x:0:0:", "[boot loader]", "daemon:x:")
_REFLECTION_MARKER_RE = re.compile(r"fzz-reflection-[a-z0-9-]+", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_FIELD_NAME_RE = re.compile(
    r"<(?:input|textarea|select)\b[^>]*\bname\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))",
    re.IGNORECASE,
)


class ReconError(ValueError):
    """Raised when the supplied target cannot be validated or reached."""


@dataclass(frozen=True)
class ReconConfig:
    url: str
    timeout: float = 10.0
    max_response_bytes: int = MAX_RESPONSE_BYTES

    def validate(self) -> str:
        parsed = urlparse(self.url.strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ReconError("El target debe usar http:// o https://")
        if not parsed.hostname:
            raise ReconError("El target debe incluir un hostname válido")
        if parsed.username or parsed.password:
            raise ReconError("No se permiten credenciales embebidas en la URL del target")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ReconError("El puerto del target no es válido") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ReconError("El puerto del target debe estar entre 1 y 65535")
        if not 0.1 <= self.timeout <= MAX_RECON_TIMEOUT:
            raise ReconError(f"El timeout de reconocimiento debe estar entre 0.1 y {MAX_RECON_TIMEOUT}")
        if not 1_024 <= self.max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ReconError(f"El límite de respuesta debe estar entre 1024 y {MAX_RESPONSE_BYTES} bytes")
        return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


@dataclass(frozen=True)
class ReconProfile:
    requested_url: str
    final_url: str
    reachable: bool
    status_code: int
    elapsed: float
    title: str | None
    content_type: str | None
    content_length: str | None
    server: str | None
    powered_by: str | None
    allowed_methods: str | None
    parameters: list[str]
    baseline_signatures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _title(body: str) -> str | None:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    return " ".join(unescape(match.group(1)).split())[:200] or None


def _parameter_candidates(url: str, body: str) -> list[str]:
    names: list[str] = []
    names.extend(name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True))
    for match in _FIELD_NAME_RE.finditer(body):
        names.append(next((group for group in match.groups() if group), ""))
    result: list[str] = []
    for name in names:
        candidate = unescape(name).strip()
        if not candidate or len(candidate) > 80 or any(char.isspace() for char in candidate):
            continue
        if candidate not in result:
            result.append(candidate)
        if len(result) >= MAX_PARAMETER_CANDIDATES:
            break
    return result


def _baseline_signatures(body: str) -> list[str]:
    signatures = [marker for marker in _BASELINE_MARKERS if marker in body]
    signatures.extend(match.lower() for match in _REFLECTION_MARKER_RE.findall(body))
    return list(dict.fromkeys(signatures))


def recon_target(config: ReconConfig, *, session: requests.Session | None = None) -> ReconProfile:
    """Validate and make one bounded GET request; no crawling or form submission occurs."""
    normalized_url = config.validate()
    client = session or requests.Session()
    started = time.monotonic()
    try:
        response = client.get(
            normalized_url,
            timeout=config.timeout,
            allow_redirects=True,
            headers={"User-Agent": "FZZ-recon/1.0 (authorized security testing)"},
        )
    except requests.RequestException as exc:
        raise ReconError(f"No se pudo contactar el target: {exc}") from exc
    elapsed = time.monotonic() - started
    body = response.content[: config.max_response_bytes].decode(response.encoding or "utf-8", errors="replace")
    final_url = str(response.url)
    return ReconProfile(
        requested_url=normalized_url,
        final_url=final_url,
        reachable=True,
        status_code=response.status_code,
        elapsed=elapsed,
        title=_title(body),
        content_type=response.headers.get("Content-Type"),
        content_length=response.headers.get("Content-Length"),
        server=response.headers.get("Server"),
        powered_by=response.headers.get("X-Powered-By"),
        allowed_methods=response.headers.get("Allow"),
        parameters=_parameter_candidates(final_url, body),
        baseline_signatures=_baseline_signatures(body),
    )


__all__ = ["ReconConfig", "ReconError", "ReconProfile", "recon_target"]
