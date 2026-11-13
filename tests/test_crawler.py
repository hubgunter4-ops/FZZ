"""Crawling opt-in y autenticación de FZZ, solo contra un servidor local.

Nunca se toca ningún host real: todas las peticiones van a un
http.server en 127.0.0.1 levantado por estos tests.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fzztool.cli import build_parser, main
from fzztool.crawler import (
    CrawlConfig,
    CrawlError,
    build_auth_headers,
    crawl_target,
    parse_auth_header,
)
from fzztool.fuzzer import FuzzConfig, fuzz_target
from fzztool.payloads import Payload
from fzztool.recon import ReconConfig, recon_target
from fzztool.report import build_report, report_markdown

TOKEN = "Bearer TOKEN-SECRETO-12345"
COOKIE = "session=COOKIE-SECRETA-67890"

PAGES = {
    "/": (
        '<html><title>Home</title><body>'
        '<a href="/a">a</a><a href="/b">b</a>'
        '<a href="https://example.com/fuera">externo</a>'
        '<a href="http://other.test/fuera">otro-host</a>'
        '<a href="mailto:x@example.com">mail</a>'
        '<a href="javascript:void(0)">js</a>'
        "</body></html>"
    ),
    "/a": (
        '<html><title>A</title><body>'
        '<a href="/a/deep">deep</a><a href="/">home</a>'
        '<form><input name="q"></form>'
        "</body></html>"
    ),
    "/a/deep": (
        '<html><title>Deep</title><body>'
        '<a href="/a/deeper">deeper</a>'
        '<form><input name="deep_param"></form>'
        "</body></html>"
    ),
    "/a/deeper": "<html><title>Deeper</title><body>fin</body></html>",
    "/b": (
        '<html><title>B</title><body>'
        '<a href="/redir">redir</a><a href="/redir-fuera">redir-fuera</a>'
        "</body></html>"
    ),
}


class _Handler(BaseHTTPRequestHandler):
    log = []  # lista compartida: (path, dict(headers))

    def log_message(self, *args):  # silenciar el log del servidor
        pass

    def _record(self):
        _Handler.log.append((self.path, dict(self.headers)))

    def do_GET(self):
        self._record()
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/a")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/redir-fuera":
            self.send_response(302)
            self.send_header("Location", "https://example.com/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = PAGES.get(self.path)
        if body is None:
            self.send_response(404)
            body = "nope"
        else:
            self.send_response(200)
        data = body.encode()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def local_server():
    _Handler.log.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_crawl_stays_in_scope_and_respects_depth(local_server):
    result = crawl_target(CrawlConfig(local_server + "/", max_depth=2))
    paths = {p for p in (u.replace(local_server, "") for u in result.urls)}
    assert paths == {"/", "/a", "/b", "/a/deep", "/redir", "/redir-fuera"}
    assert "/a/deeper" not in paths
    assert result.skipped_off_scope == 2  # example.com y other.test
    assert not any("example.com" in u or "other.test" in u for u in result.urls)
    assert "q" in result.parameters and "deep_param" in result.parameters


def test_crawl_max_depth_1(local_server):
    result = crawl_target(CrawlConfig(local_server + "/", max_depth=1))
    paths = {u.replace(local_server, "") for u in result.urls}
    assert paths == {"/", "/a", "/b"}
    assert "/a/deep" not in paths


def test_crawl_max_urls_cap(local_server):
    result = crawl_target(CrawlConfig(local_server + "/", max_depth=2, max_urls=2))
    assert len(result.urls) == 2


def test_crawl_sends_auth_only_to_target(local_server):
    config = CrawlConfig(local_server + "/", auth_header=f"Authorization: {TOKEN}", auth_cookie=COOKIE)
    assert config.headers_for("https://example.com/") == {}
    assert config.headers_for(local_server + "/a")["Authorization"] == TOKEN
    result = crawl_target(config)
    assert result.auth_used is True
    assert _Handler.log, "el servidor local no recibió peticiones"
    for _, headers in _Handler.log:
        assert headers.get("Authorization") == TOKEN
        assert headers.get("Cookie") == COOKIE


def test_crawl_redirect_off_origin_never_receives_auth():
    seen_urls = []

    class FakeResponse:
        def __init__(self, status, location=None):
            self.status_code = status
            self.url = "http://test.local/redir"
            self.encoding = "utf-8"
            self.content = b""
            self.headers = {"Location": location} if location else {}

    class FakeSession:
        def get(self, url, **kwargs):
            seen_urls.append((url, kwargs.get("headers", {})))
            if url.endswith("/redir"):
                return FakeResponse(302, "https://example.com/")
            return FakeResponse(200)

    result = crawl_target(
        CrawlConfig("http://test.local/redir", auth_header=f"Authorization: {TOKEN}"),
        session=FakeSession(),
    )
    assert result.urls == ["http://test.local/redir"]
    assert all("example.com" not in url for url, _ in seen_urls)
    assert all(h.get("Authorization") == TOKEN for _, h in seen_urls)


def test_token_never_in_crawl_dict_or_report(local_server):
    result = crawl_target(
        CrawlConfig(local_server + "/", auth_header=f"Authorization: {TOKEN}", auth_cookie=COOKIE)
    )
    blob = json.dumps(result.to_dict(), ensure_ascii=False)
    assert TOKEN not in blob and COOKIE not in blob
    assert "TOKEN-SECRETO" not in blob and "COOKIE-SECRETA" not in blob
    profile = recon_target(ReconConfig(local_server + "/"))
    report = build_report(profile, [], mode="recon", crawl=result.to_dict())
    blob = json.dumps(report, ensure_ascii=False) + report_markdown(report)
    assert TOKEN not in blob and COOKIE not in blob


def test_no_crawl_without_flag(local_server, capsys):
    _Handler.log.clear()
    assert main(["recon", "--url", local_server + "/", "--json-output"]) == 0
    out = capsys.readouterr().out
    assert '"crawl"' not in out
    assert len(_Handler.log) == 1  # solo la GET de recon, sin crawling


def test_cli_recon_crawl_with_auth(local_server, capsys):
    assert (
        main(
            [
                "recon",
                "--url",
                local_server + "/",
                "--crawl",
                "--auth-header",
                f"Authorization: {TOKEN}",
                "--json-output",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert TOKEN not in out
    data = json.loads(out)
    assert data["crawl"]["visited"] >= 4
    assert data["crawl"]["auth_used"] is True
    assert data["crawl"]["skipped_off_scope"] == 2


def test_cli_recon_crawl_merges_parameters_and_reports(local_server, tmp_path, capsys):
    report = tmp_path / "report.json"
    assert (
        main(
            [
                "check",
                "--url",
                local_server + "/a",
                "--auto-params",
                "--crawl",
                "--max-depth",
                "1",
                "--report",
                str(report),
            ]
        )
        in (0, 1)
    )
    data = json.loads(report.read_text(encoding="utf-8"))
    assert "crawl" in data
    assert data["crawl"]["visited"] >= 1
    assert "q" in data["recon"]["parameters"]


def test_auth_validation_rejects_bad_input():
    with pytest.raises(CrawlError):
        parse_auth_header("sin-dos-puntos")
    with pytest.raises(CrawlError):
        parse_auth_header("Authorization: token\nEvil: 1")
    with pytest.raises(CrawlError):
        build_auth_headers(auth_cookie="sin-igual")
    with pytest.raises(CrawlError):
        CrawlConfig("http://test.local/", max_depth=3).validate()
    with pytest.raises(CrawlError):
        CrawlConfig("http://test.local/", max_urls=31).validate()
    with pytest.raises(CrawlError):
        CrawlConfig("http://test.local/", max_depth=2, max_urls=30, auth_header="X: a\nb").validate()


def test_recon_with_auth_does_not_follow_off_origin_redirect():
    calls = []

    class FakeResponse:
        def __init__(self, status, location=None):
            self.status_code = status
            self.url = "http://test.local/"
            self.encoding = "utf-8"
            self.content = b"<title>t</title>"
            self.headers = {"Content-Type": "text/html", "Location": location} if location else {"Content-Type": "text/html"}

    class FakeSession:
        def get(self, url, **kwargs):
            calls.append((url, kwargs.get("headers", {})))
            if url == "http://test.local/":
                return FakeResponse(302, "https://example.com/")
            return FakeResponse(200)

    profile = recon_target(
        ReconConfig("http://test.local/", headers={"Authorization": TOKEN}), session=FakeSession()
    )
    assert profile.status_code == 302
    assert len(calls) == 1  # no se siguió la redirección fuera de origen
    assert calls[0][1]["Authorization"] == TOKEN


def test_fuzz_sends_auth_headers(local_server):
    seen = []

    class FakeResponse:
        status_code = 200
        url = local_server + "/a"
        encoding = "utf-8"
        headers = {"Content-Type": "text/html"}

        def __init__(self):
            self.text = "ok"
            self.content = b"ok"

    class FakeSession:
        def get(self, url, **kwargs):
            seen.append(kwargs.get("headers"))
            return FakeResponse()

    results = fuzz_target(
        FuzzConfig(local_server + "/a", "q", pause=0, headers={"Authorization": TOKEN}),
        [Payload("xss", "reflected", "<x>")],
        session=FakeSession(),
        perform_recon=False,
        recon_profile=None,
    )
    assert len(results) == 1
    assert seen == [{"Authorization": TOKEN}]


def test_cli_parser_accepts_new_flags():
    args = build_parser().parse_args(
        ["recon", "--url", "http://test.local/", "--crawl", "--max-depth", "1", "--max-urls", "5",
         "--auth-header", "Authorization: Bearer x", "--auth-cookie", "s=v"]
    )
    assert args.crawl is True and args.max_depth == 1 and args.max_urls == 5
    assert args.auth_header == "Authorization: Bearer x"
