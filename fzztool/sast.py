"""Lightweight regex-based JavaScript SAST scanner."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import re
from typing import Any

MAX_FILE_SIZE = 2_000_000
MAX_FILES = 1_000

RULES: dict[str, tuple[str, str]] = {
    "SQL_INJECTION": (r"(?:SELECT|INSERT|UPDATE|DELETE)[^\n]*(?:\\+|\$\{)[^\n]*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Posible inyección SQL: consulta construida con entrada HTTP sin parametrización visible."),
    "XSS_REFLECTED": (r"(?:res\.(?:send|write)|response\.send)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Posible XSS reflejado: entrada HTTP enviada directamente a la respuesta."),
    "XSS_TEMPLATE": (r"`[^`]*\$\{[^}]*?(?:req\.(?:query|body|params)|request\.(?:query|body))[^}]*\}[^`]*`", "Posible XSS: dato HTTP interpolado en un template literal."),
    "OS_COMMAND": (r"(?:child_process\.)?(?:exec|execFile|spawn|fork)\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Posible OS command injection: entrada HTTP llega a una API de procesos."),
    "DYNAMIC_EVAL": (r"\beval\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Uso peligroso de eval con entrada HTTP controlable."),
}


@dataclass(frozen=True)
class SastFinding:
    rule: str
    file: str
    line: int
    detail: str
    code: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def scan_file(path: str | Path, *, max_size: int = MAX_FILE_SIZE) -> list[SastFinding]:
    file_path = Path(path)
    if file_path.suffix != ".js":
        return []
    if file_path.stat().st_size > max_size:
        raise ValueError(f"El archivo supera el límite de {max_size} bytes: {file_path}")
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"No se pudo leer {file_path}: {exc}") from exc
    findings: list[SastFinding] = []
    for number, code in enumerate(lines, 1):
        for rule, (pattern, detail) in RULES.items():
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(SastFinding(rule, str(file_path), number, detail, code.strip()))
    return findings


def scan_directory(directory: str | Path, *, max_size: int = MAX_FILE_SIZE, max_files: int = MAX_FILES) -> list[SastFinding]:
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"El directorio no existe: {root}")
    files = sorted(path for path in root.rglob("*.js") if path.is_file())
    if len(files) > max_files:
        raise ValueError(f"El escaneo supera el límite de {max_files} archivos JavaScript")
    findings: list[SastFinding] = []
    for path in files:
        findings.extend(scan_file(path, max_size=max_size))
    return findings


__all__ = ["RULES", "SastFinding", "scan_file", "scan_directory"]
