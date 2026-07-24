# src/spyscan/app/launch.py
"""Desktop window launcher for the spyscan app.

Starts the localhost-only Flask server in a daemon thread on a free port, then
opens a native pywebview window pointing at it. If pywebview is unavailable or
its window fails to init (missing runtime, headless box), it FALLS BACK to
opening the URL in the default browser and keeps the server running. Either way
the chosen path is logged so it is never silent.
"""
from __future__ import annotations
import os
import socket
import sys
import threading
import time
import webbrowser
from wsgiref.simple_server import make_server, WSGIServer
from socketserver import ThreadingMixIn

from spyscan.app.server import create_app

HOST = "127.0.0.1"


def _env_port() -> int | None:
    """Honor SPYSCAN_PORT for a fixed bind (testing the frozen build). Invalid /
    unset -> None, so the normal free-port path runs."""
    raw = os.environ.get("SPYSCAN_PORT")
    if not raw:
        return None
    try:
        p = int(raw)
        return p if 0 < p < 65536 else None
    except ValueError:
        return None


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Threaded WSGI server so a slow /api/scan request does not block the UI
    fetching /api/status etc. daemon_threads so it dies with the process."""
    daemon_threads = True


def _free_port() -> int:
    """Ask the OS for an unused localhost port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(port: int | None = None, log=print) -> tuple[str, "WSGIServer", threading.Thread]:
    """Start the Flask app on 127.0.0.1:<port> in a daemon thread.

    Returns (url, httpd, thread). Bind is localhost-only -- never 0.0.0.0.

    Port precedence: explicit arg > SPYSCAN_PORT env (test/debug fixed bind) >
    an OS-assigned free port.
    """
    port = port or _env_port() or _free_port()
    app = create_app()
    httpd = make_server(HOST, port, app, server_class=_ThreadingWSGIServer)
    t = threading.Thread(target=httpd.serve_forever, name="spyscan-server", daemon=True)
    t.start()
    url = f"http://{HOST}:{port}/"
    log(f"[spyscan] local server on {url}")
    return url, httpd, t


def _wait_until_up(url: str, timeout: float = 5.0) -> bool:
    """Poll the server until it answers, so we don't open a window too early."""
    import urllib.request
    deadline = time.time() + timeout
    status_url = url.rstrip("/") + "/api/status"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(status_url, timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.1)
    return False


def open_window(url: str, log=print) -> str:
    """Open a native pywebview window, or fall back to the browser.

    Returns "pywebview" or "browser" (the path actually taken) so callers/tests
    can assert which engaged. NEVER raises on a GUI failure -- the fallback is
    the safety net.
    """
    try:
        import webview  # pywebview
    except Exception as e:
        log(f"[spyscan] pywebview unavailable ({e!r}); opening in browser")
        webbrowser.open(url)
        return "browser"

    try:
        webview.create_window("spyscan", url, width=980, height=820, min_size=(720, 600))
        # start() blocks until the window is closed; gui=None lets pywebview pick
        # the platform backend. Any backend/runtime failure -> browser fallback.
        webview.start()
        log("[spyscan] pywebview window closed; shutting down")
        return "pywebview"
    except Exception as e:
        log(f"[spyscan] pywebview window failed ({e!r}); opening in browser")
        webbrowser.open(url)
        return "browser"


def _write_url_file(url: str) -> None:
    """Record the chosen URL next to the exe / project root so an external caller
    (e.g. a smoke test of the frozen build) can discover the free port. Best
    effort -- never blocks startup if the dir is read-only."""
    try:
        from spyscan.resources import app_base
        (app_base() / "spyscan_url.txt").write_text(url, encoding="utf-8")
    except Exception:
        pass


def main(argv=None) -> int:
    """Entry point for `spyscan app`, `python -m spyscan.app`, spyscan-app."""
    url, httpd, _ = start_server()
    _write_url_file(url)
    _wait_until_up(url)
    try:
        path = open_window(url)
    finally:
        # Clean shutdown of the server once the window closes (pywebview path).
        # In the browser-fallback path the window call returns immediately, so we
        # keep the server alive in the foreground until interrupted.
        pass

    if path == "browser":
        print("[spyscan] server running; press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[spyscan] stopping server")
        finally:
            httpd.shutdown()
        return 0

    # pywebview path: window already closed -> tear the server down.
    httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
