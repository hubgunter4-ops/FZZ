from fzztool.recon import ReconConfig, ReconError, recon_target


class FakeResponse:
    status_code = 200
    url = "https://example.test/home"
    encoding = "utf-8"
    content = b'<html><title> Demo App </title><body><form><input name="query"><select name="category"></select></form></body></html>'
    headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": "54",
        "Server": "demo-server",
        "X-Powered-By": "demo-runtime",
        "Allow": "GET, POST",
    }


class FakeSession:
    def __init__(self):
        self.calls = []
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


def test_recon_validates_target_and_returns_profile():
    session = FakeSession()
    profile = recon_target(ReconConfig("HTTPS://example.test/path#ignored"), session=session)
    assert profile.reachable is True
    assert profile.status_code == 200
    assert profile.requested_url == "https://example.test/path"
    assert profile.title == "Demo App"
    assert profile.parameters == ["query", "category"]
    assert profile.server == "demo-server"
    assert session.calls[0][1]["allow_redirects"] is True


def test_recon_rejects_credentials_and_invalid_scheme():
    for url in ("ftp://example.test", "https://user:pass@example.test"):
        try:
            ReconConfig(url).validate()
        except ReconError:
            pass
        else:
            raise AssertionError("expected target validation error")
