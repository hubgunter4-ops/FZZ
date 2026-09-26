"""Command line interface for FZZ authorized security testing."""
from __future__ import annotations

import argparse
import json
import sys

from .fuzzer import FuzzConfig, fuzz_target
from .payloads import default_check_file, default_payload_file, load_payloads
from .recon import ReconConfig, recon_target
from .report import build_report, write_report
from .sast import scan_directory

DISCLAIMER = "Solo use FZZ contra sistemas propios o con autorización explícita. Los hallazgos son indicativos."


def _add_check_options(command: argparse.ArgumentParser, *, payload_default: str) -> None:
    command.add_argument("--url", required=True)
    command.add_argument("--param", dest="parameter", help="Parámetro a probar; incompatible con --auto-params")
    command.add_argument("--auto-params", action="store_true", help="Detectar parámetros de query/formulario durante recon y probarlos")
    command.add_argument("--payloads", default=payload_default)
    command.add_argument("--method", choices=["GET", "POST"], default="GET")
    command.add_argument("--body", choices=["form", "json"], default="form", help="Formato para POST")
    command.add_argument("--timeout", type=float, default=10.0)
    command.add_argument("--pause", type=float, default=0.5)
    command.add_argument("--max-requests", type=int, default=500)
    command.add_argument("--json-output", action="store_true")
    command.add_argument("--report", help="Guardar reporte detallado en JSON o Markdown")
    command.add_argument("--report-format", choices=["auto", "json", "markdown"], default="auto")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fzz", description="Fuzzing HTTP y SAST JavaScript para pruebas autorizadas.")
    parser.add_argument("--version", action="version", version="fzz 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)
    fuzz = sub.add_parser("fuzz", help="Enviar payloads YAML a un parámetro HTTP")
    _add_check_options(fuzz, payload_default=str(default_payload_file()))
    check = sub.add_parser("check", help="Ejecutar comprobaciones seguras precargadas con reporte opcional")
    _add_check_options(check, payload_default=str(default_check_file()))
    recon = sub.add_parser("recon", help="Validar y perfilar un target HTTP con una sola solicitud GET")
    recon.add_argument("--url", required=True)
    recon.add_argument("--timeout", type=float, default=10.0)
    recon.add_argument("--json-output", action="store_true")
    sast = sub.add_parser("sast", help="Escanear archivos JavaScript con reglas regex")
    sast.add_argument("directory")
    sast.add_argument("--json-output", action="store_true")
    sub.add_parser("gui", help="Abrir la interfaz Tkinter opcional")
    return parser


def _run_http_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    payloads = load_payloads(args.payloads)
    if args.auto_params and args.parameter:
        parser.error("--param y --auto-params no pueden usarse juntos")
    parameter = "auto" if args.auto_params else args.parameter
    if not parameter:
        parser.error("el comando requiere --param NOMBRE o --auto-params")
    config = FuzzConfig(args.url, parameter, args.method, args.body, args.timeout, args.pause, max_requests=args.max_requests)
    profile = recon_target(ReconConfig(config.url, min(config.timeout, 30.0)))
    results = fuzz_target(config, payloads, perform_recon=False, recon_profile=profile)
    report = build_report(profile, results, mode=args.command)
    if args.report:
        destination = write_report(report, args.report, format=args.report_format)
        print(f"Reporte guardado: {destination}", file=sys.stderr)
    data = report if args.report else {"recon": profile.to_dict(), "results": [result.to_dict() for result in results]}
    if args.json_output:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(f"Reconocimiento: {profile.status_code} | {profile.final_url} | {profile.title or 'sin título'}")
        print(f"Parámetros candidatos: {', '.join(profile.parameters) if profile.parameters else 'ninguno'}")
        for result in results:
            status = result.status_code if result.status_code is not None else "ERROR"
            print(f"{status:>5} {result.elapsed:>6.2f}s [{result.parameter}] {result.category}/{result.technique}: {result.payload}")
            for indicator in result.indicators:
                print(f"      [!] {indicator}")
            if result.error:
                print(f"      [!] {result.error}")
        print(f"Resumen: {report['summary']['findings']} indicador(es); confianza alta={report['summary']['confidence']['alta']}, media={report['summary']['confidence']['media']}, baja={report['summary']['confidence']['baja']}")
    return 1 if report["summary"]["findings"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(f"[!] {DISCLAIMER}", file=sys.stderr)
    try:
        if args.command == "gui":
            from .gui import launch
            launch()
            return 0
        if args.command in {"fuzz", "check"}:
            return _run_http_command(args, parser)
        if args.command == "recon":
            profile = recon_target(ReconConfig(args.url, args.timeout))
            if args.json_output:
                print(json.dumps(profile.to_dict(), ensure_ascii=False, indent=2))
            else:
                print(f"Target válido y accesible: {profile.final_url}")
                print(f"Estado: {profile.status_code} | Tiempo: {profile.elapsed:.2f}s")
                print(f"Título: {profile.title or 'n/d'} | Content-Type: {profile.content_type or 'n/d'}")
                print(f"Server: {profile.server or 'n/d'} | X-Powered-By: {profile.powered_by or 'n/d'}")
                print(f"Parámetros candidatos: {', '.join(profile.parameters) if profile.parameters else 'ninguno'}")
                print(f"Firmas baseline: {', '.join(profile.baseline_signatures) if profile.baseline_signatures else 'ninguna'}")
            return 0
        findings = [finding.to_dict() for finding in scan_directory(args.directory)]
        if args.json_output:
            print(json.dumps(findings, ensure_ascii=False, indent=2))
        else:
            for finding in findings:
                print(f"[!] {finding['severity'].upper()} / {finding['confidence']} | {finding['rule']} | {finding['file']}:{finding['line']} | {finding['detail']}\n    {finding['code']}")
            print(f"Escaneo finalizado: {len(findings)} hallazgo(s).")
        return 1 if findings else 0
    except ValueError as exc:
        parser.error(str(exc))
    except OSError as exc:
        print(f"[!] Error del sistema: {exc}", file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
