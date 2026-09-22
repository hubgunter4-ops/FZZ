from pathlib import Path

from fzztool.fuzzer import FuzzConfig, fuzz_target
from fzztool.payloads import load_payloads


PAYLOADS = """vulnerabilities:\n  ssti:\n    - technique: arithmetic\n      payloads: ["{{{{7*7}}}}"]\n  command:\n    - technique: file\n      payloads: ["cat /etc/passwd"]\n"""


class FakeResponse:
    status_code = 200
    def __init__(self, text):
        self.text = text


class FakeSession:
    def __init__(self):
        self.calls = []
    def get(self, url, *, params, timeout):
        self.calls.append(("GET", url, params, timeout))
        return FakeResponse("49" if "7*7" in params["q"] else "root:x:0:0:")


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
