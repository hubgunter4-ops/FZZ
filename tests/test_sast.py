from pathlib import Path

from fzztool.sast import scan_directory


def test_scans_javascript_and_reports_fields(tmp_path: Path):
    (tmp_path / "app.js").write_text("const q = req.query.q;\nres.send(`<p>${req.query.q}</p>`);\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("res.send(req.query.q)", encoding="utf-8")
    findings = scan_directory(tmp_path)
    assert findings
    assert findings[0].rule == "XSS_TEMPLATE"
    assert findings[0].file.endswith("app.js")
    assert findings[0].line == 2
    assert findings[0].code == "res.send(`<p>${req.query.q}</p>`);"


def test_clean_javascript_has_no_findings(tmp_path: Path):
    (tmp_path / "safe.js").write_text("res.send(escapeHtml(req.query.q));\n", encoding="utf-8")
    assert scan_directory(tmp_path) == []
