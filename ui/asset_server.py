import logging
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

log = logging.getLogger("swift-ui")

_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".svg": "image/svg+xml",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".mkv": "video/x-matroska",
}


class _Handler(BaseHTTPRequestHandler):
    server_version = "PrimeProxy/1.0"

    def log_message(self, fmt, *args):
        return

    def _serve(self, path):
        svc = self.server.svc
        if not svc:
            self.send_error(503)
            return
        if path != svc.allowed_path:
            self.send_error(403)
            return
        ext = os.path.splitext(path)[1].lower()
        mime = _MIME.get(ext, "application/octet-stream")
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                head = (
                    "HTTP/1.1 200 OK\r\n"
                    "Cache-Control: no-cache\r\n"
                    f"Content-Type: {mime}\r\n"
                    "Accept-Ranges: bytes\r\n"
                    f"Content-Length: {size}\r\n"
                    f"X-Content-Type-Options: nosniff\r\n"
                    "\r\n"
                )
                try:
                    self.wfile.write(head.encode("latin1"))
                    remaining = size
                    while remaining > 0:
                        chunk = fh.read(1 << 20)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
                except (BrokenPipeError, ConnectionAbortedError):
                    return
        except OSError:
            self.send_error(404)

    def do_GET(self):
        parts = urlparse(self.path)
        qs = parse_qs(parts.query)
        token = (qs.get("k") or [""])[0]
        path = (qs.get("p") or [""])[0]
        if token != self.server.token:
            self.send_error(403)
            return
        try:
            path = unquote(path)
        except Exception:
            self.send_error(400)
            return
        self._serve(path)


class _AssetServer:
    def __init__(self):
        self._token = secrets.token_urlsafe(24)
        self.allowed_path = ""
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None

    def start(self):
        with self._lock:
            if self._httpd:
                return
            self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
            self._httpd.token = self._token
            self._httpd.svc = self
            self._httpd.daemon_threads = True
            self._thread = threading.Thread(target=self._httpd.serve_forever, name="asset-srv", daemon=True)
            self._thread.start()

    def url(self, path):
        with self._lock:
            self.allowed_path = path
            port = self._httpd.server_address[1]
        from urllib.parse import quote

        return f"http://127.0.0.1:{port}/asset?k={self._token}&p={quote(path)}"

    def stop(self):
        with self._lock:
            if self._httpd:
                self._httpd.shutdown()
                self._httpd = None


_server = None
_server_lock = threading.Lock()


def url_for(path):
    global _server
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        return None
    with _server_lock:
        if _server is None:
            _server = _AssetServer()
            _server.start()
        return _server.url(path)


def is_running():
    return _server is not None and _server._httpd is not None