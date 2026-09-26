from pathlib import Path

from fzztool.fuzzer import FuzzConfig, fuzz_target
from fzztool.payloads import load_payloads
from fzztool.recon import ReconProfile


PAYLOADS = """vulnerabilities:\n  ssti:\n    - technique: arithmetic\n      payloads: ["{{{{7*7}}}}"]\n  command:\n    - technique: file\n      payloads: ["cat /etc/passwd"]\n"""


class FakeResponse:
    status_code = 200
    url = "http://test.local/search"
    encoding = "utf-8"
    headers = {"Content-Type": "text/html"}
    def __init__(self, text="<title>fixture</title>"):
        self.text = text
        self.content = text.encode()


class FakeSession:
    def __init__(self):
        self.calls = []
    def get(self, url, *, params=None, timeout, **kwargs):
        self.calls.append(("GET", url, params, timeout))
        if params is None:
            return FakeResponse()
        value = next(iter(params.values()))
        return FakeResponse("49" if "7*7" in value else "root:x:0:0:")


def test_loads_and_fuzzes_get_with_indicators(tmp_path: Path):
    file = tmp_path / "payloads.yml"
    file.write_text(PAYLOADS, encoding="utf-8")
    payloads = load_payloads(file)
    config = FuzzConfig("http://test.local/search", "q", pause=0, max_requests=10)
    results = fuzz_target(config, payloads, session=FakeSession())
    assert results[0].status_code == 200
    assert any("SSTI" in item for item in results[0].indicators)
    assert any("archivo" in item for item in results[1].indicators)


def test_rejects_bad_config():
    try:
        FuzzConfig("ftp://bad", "q").validate()
    except ValueError as exc:
        assert "http" in str(exc)
    else:
        raise AssertionError("expected validation error")


def test_auto_parameters_fuzzes_recon_candidates_with_request_cap(tmp_path: Path):
    file = tmp_path / "payloads.yml"
    file.write_text("vulnerabilities:\n  xss:\n    - technique: reflected\n      payloads: ['<x>']\n", encoding="utf-8")
    payloads = load_payloads(file)
    profile = ReconProfile("http://test.local/search", "http://test.local/search", True, 200, 0.01, "fixture", "text/html", None, None, None, None, ["q", "term"])
    session = FakeSession()
    results = fuzz_target(FuzzConfig("http://test.local/search", "auto", pause=0, max_requests=2), payloads, session=session, perform_recon=False, recon_profile=profile)
    assert [result.parameter for result in results] == ["q", "term"]
    assert [call[2] for call in session.calls] == [{"q": "<x>"}, {"term": "<x>"}]


def test_auto_parameters_rejects_profile_without_candidates(tmp_path: Path):
    file = tmp_path / "payloads.yml"
    file.write_text("vulnerabilities:\n  xss:\n    - technique: reflected\n      payloads: ['<x>']\n", encoding="utf-8")
    profile = ReconProfile("http://test.local", "http://test.local", True, 200, 0.01, None, "text/html", None, None, None, None, [])
    try:
        fuzz_target(FuzzConfig("http://test.local", "auto", pause=0), load_payloads(file), perform_recon=False, recon_profile=profile)
    except ValueError as exc:
        assert "parámetros candidatos" in str(exc)
    else:
        raise AssertionError("expected automatic parameter validation error")
