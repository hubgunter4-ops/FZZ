from pathlib import Path

from fzztool.cli import main


def test_sast_cli_returns_findings_code(tmp_path: Path, capsys):
    (tmp_path / "bad.js").write_text("res.send(req.query.q);\n", encoding="utf-8")
    assert main(["sast", str(tmp_path), "--json-output"]) == 1
    assert '"rule": "XSS_REFLECTED"' in capsys.readouterr().out


def test_sast_cli_clean_returns_zero(tmp_path: Path):
    (tmp_path / "safe.js").write_text("console.log('ok');\n", encoding="utf-8")
    assert main(["sast", str(tmp_path), "--json-output"]) == 0
