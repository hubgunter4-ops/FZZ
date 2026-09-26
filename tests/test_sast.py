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


def test_detects_weak_crypto_and_exposed_secret_with_severity(tmp_path: Path):
    (tmp_path / "crypto.js").write_text(
        "const digest = crypto.createHash('md5');\n"
        "const tls = { rejectUnauthorized: false };\n"
        "const apiKey = 'AKIA1234567890ABCDEF';\n",
        encoding="utf-8",
    )
    findings = scan_directory(tmp_path)
    rules = {finding.rule: finding for finding in findings}
    assert rules["WEAK_CRYPTO_HASH"].severity == "medium"
    assert rules["TLS_WEAK_CONFIGURATION"].severity == "high"
    assert rules["EXPOSED_ACCESS_KEY"].severity == "critical"
    assert all(finding.confidence == "high" for finding in findings)


def test_detects_private_key_and_hardcoded_secret(tmp_path: Path):
    (tmp_path / "secrets.js").write_text(
        "const privateKey = `-----BEGIN PRIVATE KEY-----`;\n"
        "const password = 'correct-horse-battery';\n",
        encoding="utf-8",
    )
    rules = {finding.rule for finding in scan_directory(tmp_path)}
    assert {"EXPOSED_PRIVATE_KEY", "HARDCODED_SECRET"} <= rules


def test_scans_typescript_and_tsx_with_language_specific_rules(tmp_path: Path):
    (tmp_path / "service.ts").write_text(
        "function parse(input: any) { return input as any; }\n",
        encoding="utf-8",
    )
    (tmp_path / "component.tsx").write_text(
        "export function View({ html }: Props) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }\n",
        encoding="utf-8",
    )
    findings = scan_directory(tmp_path)
    rules = {finding.rule for finding in findings}
    assert {"TS_UNSAFE_ANY", "TS_ASSERTION_ANY", "TSX_DANGEROUS_HTML"} <= rules
    assert {finding.language for finding in findings} == {"TypeScript", "TSX"}


def test_scan_file_ignores_unsupported_extensions(tmp_path: Path):
    python_file = tmp_path / "service.py"
    python_file.write_text("password = 'fixture-only-value'\n", encoding="utf-8")
    assert scan_directory(tmp_path) == []
