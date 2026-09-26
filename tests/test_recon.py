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


def test_recon_discovers_query_and_form_parameters_without_duplicates():
    class QueryResponse(FakeResponse):
        url = "https://example.test/search?query=old&sort=asc"
        content = b'<form><input name="query"><input name="filter"><textarea name="sort"></textarea></form>'

    class QuerySession(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return QueryResponse()

    profile = recon_target(ReconConfig("https://example.test/search"), session=QuerySession())
    assert profile.parameters == ["query", "sort", "filter"]


def test_recon_limits_parameter_candidates():
    class ManyFieldsResponse(FakeResponse):
        content = ("<form>" + "".join(f'<input name="field{i}">' for i in range(40)) + "</form>").encode()

    class ManyFieldsSession(FakeSession):
        def get(self, url, **kwargs):
            return ManyFieldsResponse()

    profile = recon_target(ReconConfig("https://example.test/search"), session=ManyFieldsSession())
    assert len(profile.parameters) == 32
    assert profile.parameters[-1] == "field31"


def test_recon_rejects_credentials_and_invalid_scheme():
    for url in ("ftp://example.test", "https://user:pass@example.test"):
        try:
            ReconConfig(url).validate()
        except ReconError:
            pass
        else:
            raise AssertionError("expected target validation error")
