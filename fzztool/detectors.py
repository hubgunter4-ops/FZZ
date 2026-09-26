"""Conservative response indicators with baseline-aware confidence levels."""
from __future__ import annotations

import re
from typing import Iterable

from .payloads import Payload

_SSTI_EXPRESSIONS = re.compile(r"(?:\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\})", re.I)
_REFLECTION_MARKER = re.compile(r"fzz-reflection-[a-z0-9-]+", re.I)
_FILE_MARKERS = ("root:x:0:0:", "[boot loader]", "daemon:x:")
_TIME_MARKERS = re.compile(r"\b(?:sleep|benchmark|pg_sleep|waitfor|timeout|delay)\b", re.I)


def _append_unique(indicators: list[dict[str, str]], code: str, detail: str, confidence: str) -> None:
    if not any(item["code"] == code for item in indicators):
        indicators.append({"code": code, "detail": detail, "confidence": confidence})


def detect_indicators(
    payload: Payload,
    body: str,
    elapsed: float,
    *,
    timing_threshold: float,
    baseline_signatures: Iterable[str] = (),
) -> list[dict[str, str]]:
    """Return structured indicators, excluding signatures observed in the baseline response."""
    baseline = set(baseline_signatures)
    indicators: list[dict[str, str]] = []
    reflection = _REFLECTION_MARKER.search(payload.value)
    if reflection and _REFLECTION_MARKER.search(body) and reflection.group(0).lower() not in {item.lower() for item in baseline}:
        _append_unique(indicators, "REFLECTION", "El token sintético aparece en la respuesta; requiere confirmar el contexto de salida.", "alta")
    if _SSTI_EXPRESSIONS.search(payload.value) and "49" in body and "49" not in baseline:
        _append_unique(indicators, "SSTI_EVALUATED", "La respuesta contiene 49, resultado esperado de la expresión controlada; requiere confirmar el contexto.", "media")
    for marker in _FILE_MARKERS:
        if marker in body and marker not in baseline:
            _append_unique(indicators, "SENSITIVE_MARKER", f"lectura de archivo/OS command: la respuesta contiene el marcador {marker!r}; puede ser contenido legítimo o un indicador de lectura no autorizada.", "baja")
    if elapsed >= timing_threshold and _TIME_MARKERS.search(payload.value):
        _append_unique(indicators, "TIMING_ANOMALY", f"Respuesta de {elapsed:.2f}s frente al umbral {timing_threshold:.2f}s; no confirma una inyección temporal.", "baja")
    return indicators


def indicator_details(indicators: Iterable[dict[str, str]]) -> list[str]:
    """Compatibility formatter for the existing GUI and human-readable CLI."""
    return [f"{item['code']} [{item['confidence']}]: {item['detail']}" for item in indicators]


__all__ = ["detect_indicators", "indicator_details"]
