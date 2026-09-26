from pathlib import Path

from fzztool.fuzzer import FuzzResult
from fzztool.recon import ReconProfile
from fzztool.report import build_report, write_report


def test_report_contains_confidence_summary_and_markdown(tmp_path: Path):
    profile = ReconProfile("http://test.local", "http://test.local", True, 200, 0.01, "Fixture", "text/html", None, None, None, None, ["q"])
    result = FuzzResult(
        "reflection", "safe marker", "q", "fzz-reflection-check-9d3c", 200, 12, 0.02,
        ["REFLECTION [alta]: token"],
        [{"code": "REFLECTION", "detail": "token", "confidence": "alta"}],
    )
    report = build_report(profile, [result], mode="check")
    assert report["summary"]["confidence"]["alta"] == 1
    destination = write_report(report, tmp_path / "report.md")
    assert "FZZ — Reporte de comprobación autorizada" in destination.read_text(encoding="utf-8")
    assert "REFLECTION" in destination.read_text(encoding="utf-8")


def test_report_json_preserves_structured_findings(tmp_path: Path):
    profile = ReconProfile("http://test.local", "http://test.local", True, 200, 0.01, None, "text/html", None, None, None, None, [])
    report = build_report(profile, [], mode="check")
    destination = write_report(report, tmp_path / "report.json")
    assert '"findings": []' in destination.read_text(encoding="utf-8")
