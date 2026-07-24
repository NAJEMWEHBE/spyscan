# tests/test_app_launch.py
import urllib.request

from spyscan.app import launch


def test_start_server_serves_status_on_localhost():
    url, httpd, t = launch.start_server(log=lambda *a: None)
    try:
        assert url.startswith("http://127.0.0.1:")
        assert launch._wait_until_up(url, timeout=5.0)
        with urllib.request.urlopen(url.rstrip("/") + "/api/status", timeout=2) as r:
            assert r.status == 200
            body = r.read()
        assert b"baseline_exists" in body
    finally:
        httpd.shutdown()


def test_env_port_parsing(monkeypatch):
    monkeypatch.delenv("SPYSCAN_PORT", raising=False)
    assert launch._env_port() is None
    monkeypatch.setenv("SPYSCAN_PORT", "8799")
    assert launch._env_port() == 8799
    monkeypatch.setenv("SPYSCAN_PORT", "notaport")
    assert launch._env_port() is None
    monkeypatch.setenv("SPYSCAN_PORT", "70000")  # out of range
    assert launch._env_port() is None


def test_start_server_honors_env_port(monkeypatch):
    monkeypatch.setenv("SPYSCAN_PORT", "8771")
    url, httpd, t = launch.start_server(log=lambda *a: None)
    try:
        assert url == "http://127.0.0.1:8771/"
    finally:
        httpd.shutdown()


def test_open_window_falls_back_to_browser_when_pywebview_missing(monkeypatch):
    # force the `import webview` inside open_window to fail
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "webview":
            raise ImportError("no pywebview in this test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    opened = {}
    monkeypatch.setattr(launch.webbrowser, "open", lambda u: opened.setdefault("url", u))

    path = launch.open_window("http://127.0.0.1:9/", log=lambda *a: None)
    assert path == "browser"
    assert opened["url"] == "http://127.0.0.1:9/"


def test_open_window_falls_back_when_window_init_raises(monkeypatch):
    # webview imports fine but create_window blows up -> still falls back
    import types
    fake = types.SimpleNamespace(
        create_window=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no display")),
        start=lambda *a, **k: None,
    )
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "webview":
            return fake
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    opened = {}
    monkeypatch.setattr(launch.webbrowser, "open", lambda u: opened.setdefault("url", u))

    path = launch.open_window("http://127.0.0.1:9/", log=lambda *a: None)
    assert path == "browser"
    assert opened["url"] == "http://127.0.0.1:9/"
