from pathlib import Path

from fzztool.cli import main
from fzztool.fuzzer import FuzzResult
from fzztool.recon import ReconProfile


def test_sast_cli_returns_findings_code(tmp_path: Path, capsys):
    (tmp_path / "bad.js").write_text("res.send(req.query.q);\n", encoding="utf-8")
    assert main(["sast", str(tmp_path), "--json-output"]) == 1
    assert '"rule": "XSS_REFLECTED"' in capsys.readouterr().out


def test_sast_cli_clean_returns_zero(tmp_path: Path):
    (tmp_path / "safe.js").write_text("console.log('ok');\n", encoding="utf-8")
    assert main(["sast", str(tmp_path), "--json-output"]) == 0


def test_http_cli_returns_execution_error_when_a_request_fails(monkeypatch, capsys):
    profile = ReconProfile(
        "http://test.local/", "http://test.local/", True, 200, 0.01,
        None, "text/html", None, None, None, None, [],
    )
    failed_result = FuzzResult(
        "reflection", "fixture", "q", "marker", None, 0, 0.01, [], [],
        "connection refused",
    )
    monkeypatch.setattr("fzztool.cli.recon_target", lambda config: profile)
    monkeypatch.setattr("fzztool.cli.fuzz_target", lambda *args, **kwargs: [failed_result])

    exit_code = main([
        "fuzz", "--url", "http://test.local/", "--param", "q",
        "--pause", "0", "--json-output",
    ])

    assert exit_code == 3
    assert '"error": "connection refused"' in capsys.readouterr().out
