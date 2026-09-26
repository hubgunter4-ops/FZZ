"""Payload loading and validation for authorized security tests."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

import yaml

MAX_PAYLOAD_FILE_SIZE = 1_000_000


@dataclass(frozen=True)
class Payload:
    category: str
    technique: str
    value: str


def load_payloads(path: str | Path, *, max_size: int = MAX_PAYLOAD_FILE_SIZE) -> list[Payload]:
    """Load the repository YAML schema safely and return flattened payloads."""
    payload_path = Path(path)
    if not payload_path.is_file():
        raise ValueError(f"El archivo de payloads no existe: {payload_path}")
    if payload_path.stat().st_size > max_size:
        raise ValueError(f"El archivo de payloads supera el límite de {max_size} bytes")
    try:
        document = yaml.safe_load(payload_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"No se pudo leer YAML: {exc}") from exc
    return normalize_payloads(document)


def normalize_payloads(document: Any) -> list[Payload]:
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), dict):
        raise ValueError("El YAML debe contener una clave 'vulnerabilities' de tipo mapa")
    result: list[Payload] = []
    for category, techniques in document["vulnerabilities"].items():
        if not isinstance(category, str) or not isinstance(techniques, list):
            raise ValueError("Cada categoría debe tener una lista de técnicas")
        for technique in techniques:
            if not isinstance(technique, dict):
                raise ValueError(f"Técnica inválida en {category}")
            name = str(technique.get("technique", "Sin técnica"))
            values = technique.get("payloads", [])
            if not isinstance(values, list):
                raise ValueError(f"'payloads' debe ser una lista en {category}/{name}")
            for value in values:
                if not isinstance(value, (str, int, float)):
                    raise ValueError(f"Payload inválido en {category}/{name}")
                result.append(Payload(category, name, str(value)))
    if not result:
        raise ValueError("El YAML no contiene payloads utilizables")
    return result


def payload_count(path: str | Path) -> int:
    return len(load_payloads(path))


def default_payload_file() -> Path:
    bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    bundled = bundle_root / "resources" / "payloads.yml"
    if bundled.is_file():
        return bundled
    return Path(__file__).resolve().parent.parent / "resources" / "payloads.yml"


def default_check_file() -> Path:
    """Return the bundled non-destructive checks dictionary."""
    bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    bundled = bundle_root / "resources" / "safe-checks.yml"
    if bundled.is_file():
        return bundled
    return Path(__file__).resolve().parent.parent / "resources" / "safe-checks.yml"


__all__ = ["Payload", "load_payloads", "normalize_payloads", "default_payload_file", "default_check_file"]
