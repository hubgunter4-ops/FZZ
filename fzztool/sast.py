"""Lightweight regex-based JavaScript SAST scanner."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Any

MAX_FILE_SIZE = 2_000_000
MAX_FILES = 1_000

# Patterns intentionally require concrete API names or secret formats to keep findings actionable.
RULES: dict[str, tuple[str, str]] = {
    "SQL_INJECTION": (r"(?:SELECT|INSERT|UPDATE|DELETE)[^\n]*(?:\\+|\$\{)[^\n]*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Posible inyección SQL: consulta construida con entrada HTTP sin parametrización visible."),
    "XSS_REFLECTED": (r"(?:res\.(?:send|write)|response\.send)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Posible XSS reflejado: entrada HTTP enviada directamente a la respuesta."),
    "XSS_TEMPLATE": (r"`[^`]*\$\{[^}]*?(?:req\.(?:query|body|params)|request\.(?:query|body))[^}]*\}[^`]*`", "Posible XSS: dato HTTP interpolado en un template literal."),
    "OS_COMMAND": (r"(?:child_process\.)?(?:exec|execFile|spawn|fork)\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Posible OS command injection: entrada HTTP llega a una API de procesos."),
    "DYNAMIC_EVAL": (r"\beval\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:query|body))", "Uso peligroso de eval con entrada HTTP controlable."),
    "WEAK_CRYPTO_HASH": (r"(?:crypto\.)?createHash\s*\(\s*[\"'](?:md5|sha-1|sha1)[\"']", "Criptografía obsoleta: MD5/SHA-1 no deben usarse para integridad resistente a colisiones o contraseñas."),
    "WEAK_CRYPTO_CIPHER": (r"(?:createCipher|createCipheriv)\s*\([^\n]*(?:des(?:-ede3)?|3des|rc[248]|aes-(?:128|192|256)-ecb)", "Criptografía mal configurada u obsoleta: cipher débil o modo ECB detectado."),
    "TLS_WEAK_CONFIGURATION": (r"(?:rejectUnauthorized\s*:\s*false|minVersion\s*:\s*[\"']TLSv?1(?:\.0)?[\"']|secureProtocol\s*:\s*[\"'](?:SSLv3|TLSv1_method)[\"'])", "Configuración TLS débil: permite certificados no verificados o protocolos obsoletos."),
    "EXPOSED_PRIVATE_KEY": (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Secreto expuesto: bloque de clave privada incluido en el código fuente."),
    "EXPOSED_ACCESS_KEY": (r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "Secreto expuesto: formato reconocible de credencial de proveedor detectado."),
    "EXPOSED_JWT": (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "Secreto expuesto: token JWT literal detectado en el código fuente."),
    "HARDCODED_SECRET": (r"\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|password|passwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']", "Secreto potencialmente expuesto: credencial literal asignada en el código; usa variables de entorno o un gestor de secretos."),
}

_SEVERITY: dict[str, str] = {
    "EXPOSED_PRIVATE_KEY": "critical",
    "EXPOSED_ACCESS_KEY": "critical",
    "EXPOSED_JWT": "high",
    "HARDCODED_SECRET": "high",
    "WEAK_CRYPTO_HASH": "medium",
    "WEAK_CRYPTO_CIPHER": "medium",
    "TLS_WEAK_CONFIGURATION": "high",
}


@dataclass(frozen=True)
class SastFinding:
    rule: str
    file: str
    line: int
    detail: str
    code: str
    severity: str = "medium"
    confidence: str = "medium"

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
                findings.append(SastFinding(rule, str(file_path), number, detail, code.strip(), _SEVERITY.get(rule, "medium"), "high"))
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
