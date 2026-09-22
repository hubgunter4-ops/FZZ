"""Conservative indicators for responses; findings are not proof of exploitation."""
from __future__ import annotations

import re

from .payloads import Payload


_SSTI_EXPRESSIONS = re.compile(r"(?:\{\{\s*7\s*\*\s*7\s*\}\}|7\s*\*\s*7|\$\{\s*7\s*\*\s*7\s*\})", re.I)
_FILE_MARKERS = ("root:x:0:0:", "[boot loader]", "daemon:x:")
_TIME_MARKERS = re.compile(r"\b(?:sleep|benchmark|pg_sleep|waitfor|timeout|delay)\b", re.I)


def detect_indicators(payload: Payload, body: str, elapsed: float, *, timing_threshold: float) -> list[str]:
    indicators: list[str] = []
    if _SSTI_EXPRESSIONS.search(payload.value) and "49" in body:
        indicators.append("SSTI: la respuesta contiene el resultado esperado de una expresión de prueba")
    if any(marker in body for marker in _FILE_MARKERS):
        indicators.append("lectura de archivo/OS command: la respuesta contiene un marcador de archivo sensible")
    if elapsed >= timing_threshold and _TIME_MARKERS.search(payload.value):
        indicators.append(f"inyección basada en tiempo: respuesta de {elapsed:.2f}s (umbral {timing_threshold:.2f}s)")
    return indicators


__all__ = ["detect_indicators"]
