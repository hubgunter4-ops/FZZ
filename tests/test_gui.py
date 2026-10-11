from fzztool.fuzzer import FuzzResult
from fzztool.gui import FZZApp
from fzztool.recon import ReconProfile


class FakeWidget:
    def __init__(self):
        self.calls = []

    def configure(self, **kwargs):
        self.calls.append(kwargs)


class FakeRoot:
    def __init__(self):
        self.callbacks = []

    def after(self, delay, callback, *args):
        self.callbacks.append((delay, callback, args))


def test_scheduled_error_preserves_details_until_ui_callback_runs():
    app = FZZApp.__new__(FZZApp)
    app.root = FakeRoot()

    try:
        raise ValueError("invalid timeout")
    except ValueError as exc:
        app._schedule_error("Reconocimiento bloqueado", exc)

    delay, callback, args = app.root.callbacks[0]
    assert delay == 0
    assert callback.__self__ is app
    assert args == ("Reconocimiento bloqueado", "invalid timeout")


def test_gui_marks_run_partial_when_requests_fail():
    app = FZZApp.__new__(FZZApp)
    app.header_badge = FakeWidget()
    app.status = FakeWidget()
    app._set_status = lambda value, *, tone="normal": app.status.configure(text=value, tone=tone)
    result = FuzzResult(
        "reflection", "fixture", "q", "marker", None, 0, 0.01, [], [],
        "connection refused",
    )

    app._finish_run([result])

    assert app.header_badge.calls[-1]["text"] == "●  PARTIAL"
    assert app.status.calls[-1]["text"] == "Ejecución incompleta · 1 solicitud(es) fallida(s)"
    assert app.status.calls[-1]["tone"] == "danger"


def test_recon_worker_profiles_target_without_starting_fuzzing(monkeypatch):
    profile = ReconProfile(
        "http://test.local/", "http://test.local/", True, 200, 0.01,
        None, "text/html", None, None, None, None, [],
    )
    requested = []
    monkeypatch.setattr("fzztool.gui.recon_target", lambda config: requested.append(config) or profile)
    app = FZZApp.__new__(FZZApp)
    app.root = FakeRoot()
    updated_profiles = []
    app._update_recon = updated_profiles.append
    app._set_status = lambda value: updated_profiles.append(value)

    app._recon_worker("http://test.local/", 5.0)

    assert len(requested) == 1
    assert requested[0].url == "http://test.local/"
    assert requested[0].timeout == 5.0
    for _, callback, args in app.root.callbacks:
        callback(*args)
    assert updated_profiles == [profile, "Reconocimiento completado"]
