"""Command line interface for FZZ authorized security testing."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .fuzzer import FuzzConfig, fuzz_target
from .payloads import default_payload_file, load_payloads
from .sast import scan_directory

DISCLAIMER = "Solo use FZZ contra sistemas propios o con autorización explícita. Los hallazgos son indicativos."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fzz", description="Fuzzing HTTP y SAST JavaScript para pruebas autorizadas.")
    parser.add_argument("--version", action="version", version="fzz 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)
    fuzz = sub.add_parser("fuzz", help="Enviar payloads YAML a un parámetro HTTP")
    fuzz.add_argument("--url", required=True)
    fuzz.add_argument("--param", required=True, dest="parameter")
    fuzz.add_argument("--payloads", default=str(default_payload_file()))
    fuzz.add_argument("--method", choices=["GET", "POST"], default="GET")
    fuzz.add_argument("--body", choices=["form", "json"], default="form", help="Formato para POST")
    fuzz.add_argument("--timeout", type=float, default=10.0)
    fuzz.add_argument("--pause", type=float, default=0.5)
    fuzz.add_argument("--max-requests", type=int, default=500)
    fuzz.add_argument("--json-output", action="store_true")
    sast = sub.add_parser("sast", help="Escanear archivos JavaScript con reglas regex")
    sast.add_argument("directory")
    sast.add_argument("--json-output", action="store_true")
    sub.add_parser("gui", help="Abrir la interfaz Tkinter opcional")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(f"[!] {DISCLAIMER}", file=sys.stderr)
    try:
        if args.command == "gui":
            from .gui import launch
            launch()
            return 0
        if args.command == "fuzz":
            payloads = load_payloads(args.payloads)
            config = FuzzConfig(args.url, args.parameter, args.method, args.body, args.timeout, args.pause, max_requests=args.max_requests)
            results = fuzz_target(config, payloads)
            data = [result.to_dict() for result in results]
            if args.json_output:
                print(json.dumps(data, ensure_ascii=False, indent=2))
            else:
                for result in results:
                    status = result.status_code if result.status_code is not None else "ERROR"
                    print(f"{status:>5} {result.elapsed:>6.2f}s {result.category}/{result.technique}: {result.payload}")
                    for indicator in result.indicators:
                        print(f"      [!] {indicator}")
                    if result.error:
                        print(f"      [!] {result.error}")
            return 1 if any(item["indicators"] for item in data) else 0
        findings = [finding.to_dict() for finding in scan_directory(args.directory)]
        if args.json_output:
            print(json.dumps(findings, ensure_ascii=False, indent=2))
        else:
            for finding in findings:
                print(f"[!] {finding['rule']} | {finding['file']}:{finding['line']} | {finding['detail']}\n    {finding['code']}")
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
