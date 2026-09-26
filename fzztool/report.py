"""Detailed, reproducible reports for authorized FZZ checks."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Iterable

from .fuzzer import FuzzResult
from .recon import ReconProfile


def build_report(profile: ReconProfile, results: Iterable[FuzzResult], *, mode: str = "fuzz") -> dict:
    result_list = list(results)
    findings = [finding for result in result_list for finding in result.findings]
    confidence = {level: sum(item.get("confidence") == level for item in findings) for level in ("alta", "media", "baja")}
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "disclaimer": "Indicadores orientativos; no constituyen confirmación de explotación.",
        "recon": profile.to_dict(),
        "summary": {
            "requests": len(result_list),
            "results_with_indicators": sum(bool(result.indicators) for result in result_list),
            "findings": len(findings),
            "confidence": confidence,
        },
        "findings": [
            {
                **finding,
                "parameter": result.parameter,
                "category": result.category,
                "technique": result.technique,
                "payload": result.payload,
            }
            for result in result_list
            for finding in result.findings
        ],
        "results": [result.to_dict() for result in result_list],
    }


def report_markdown(report: dict) -> str:
    summary = report["summary"]
    recon = report["recon"]
    lines = [
        "# FZZ — Reporte de comprobación autorizada",
        "",
        f"> {report['disclaimer']}",
        "",
        f"- **Generado:** `{report['generated_at']}`",
        f"- **Modo:** `{report['mode']}`",
        f"- **Target:** `{recon['final_url']}`",
        f"- **HTTP:** `{recon['status_code']}`",
        f"- **Solicitudes:** `{summary['requests']}`",
        f"- **Resultados con indicadores:** `{summary['results_with_indicators']}`",
        f"- **Hallazgos:** `{summary['findings']}`",
        f"- **Confianza:** alta `{summary['confidence']['alta']}`, media `{summary['confidence']['media']}`, baja `{summary['confidence']['baja']}`",
        "",
        "## Reconocimiento",
        "",
        f"- Título: {recon.get('title') or 'n/d'}",
        f"- Content-Type: {recon.get('content_type') or 'n/d'}",
        f"- Parámetros candidatos: {', '.join(recon.get('parameters') or []) or 'ninguno'}",
        f"- Firmas presentes en baseline: {', '.join(recon.get('baseline_signatures') or []) or 'ninguna'}",
        "",
        "## Indicadores",
        "",
    ]
    if not report["findings"]:
        lines.append("No se detectaron indicadores con las comprobaciones ejecutadas.")
    else:
        lines.extend(["| Confianza | Código | Parámetro | Categoría | Detalle |", "|---|---|---|---|---|"])
        for finding in report["findings"]:
            detail = finding["detail"].replace("|", "\\|")
            lines.append(f"| {finding['confidence']} | `{finding['code']}` | `{finding['parameter']}` | `{finding['category']}` | {detail} |")
    lines.extend(["", "## Interpretación", "", "Los indicadores requieren revisión manual. Una coincidencia puede ser contenido legítimo o un falso positivo; el baseline y el nivel de confianza ayudan a priorizar, pero no sustituyen la validación autorizada.", ""])
    return "\n".join(lines)


def write_report(report: dict, destination: str | Path, *, format: str = "auto") -> Path:
    path = Path(destination)
    selected = format
    if selected == "auto":
        selected = "markdown" if path.suffix.lower() in {".md", ".markdown"} else "json"
    if selected not in {"json", "markdown"}:
        raise ValueError("El formato del reporte debe ser json o markdown")
    path.parent.mkdir(parents=True, exist_ok=True)
    if selected == "markdown":
        path.write_text(report_markdown(report), encoding="utf-8")
    else:
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


__all__ = ["build_report", "report_markdown", "write_report"]
