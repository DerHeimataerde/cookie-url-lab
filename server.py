#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import secrets
import threading
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

HOST = "127.0.0.1"
PORT = 8765

LOOKUP_DB: dict[str, str] = {}
LOOKUP_LOCK = threading.Lock()


def b64e(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def b64d(s: str) -> str | None:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode()).decode()
    except Exception:
        return None


def get_cookie_dict(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    raw = handler.headers.get("Cookie", "")
    jar = SimpleCookie()
    jar.load(raw)
    return {k: morsel.value for k, morsel in jar.items()}


def token_for(user_id: str) -> str:
    token = secrets.token_urlsafe(16)
    with LOOKUP_LOCK:
        LOOKUP_DB[token] = user_id
    return token


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LocalTrackerLab/0.1"

    def log_message(self, fmt: str, *args):
        # Keep stdout readable.
        print(f"[{self.log_date_time_string()}] {self.address_string()} - {fmt % args}")

    def _send_html(self, html: str, status: int = 200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: dict, status: int = 200):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _set_cookie(self, name: str, value: str, path: str = "/"):
        self.send_header("Set-Cookie", f"{name}={value}; Path={path}; SameSite=Lax")

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        cookies = get_cookie_dict(self)

        if parsed.path == "/":
            html = """
            <h1>Local Tracker Lab</h1>
            <p>Endpoints:</p>
            <ul>
              <li><a href='/site/plain?cid=user-123'>/site/plain?cid=user-123</a></li>
              <li><a href='/site/base64?cid=user-123'>/site/base64?cid=user-123</a></li>
              <li><a href='/site/split?cid=user-123'>/site/split?cid=user-123</a></li>
              <li><a href='/site/lookup?cid=user-123'>/site/lookup?cid=user-123</a></li>
              <li><a href='/site/random'>/site/random</a></li>
              <li><a href='/debug/db'>/debug/db</a></li>
            </ul>
            """
            self._send_html(html)
            return

        if parsed.path == "/debug/db":
            with LOOKUP_LOCK:
                snapshot = dict(LOOKUP_DB)
            self._send_json({"lookup_db": snapshot, "cookies_seen": cookies})
            return

        # Site endpoints simulate first-party pages that route through a tracker.
        if parsed.path == "/site/plain":
            cid = qs.get("cid", ["user-123"])[0]
            loc = f"/tracker/plain?xid={quote(cid)}"
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        if parsed.path == "/site/base64":
            cid = qs.get("cid", ["user-123"])[0]
            loc = f"/tracker/base64?xid={quote(b64e(cid))}"
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        if parsed.path == "/site/split":
            cid = qs.get("cid", ["user-123"])[0]
            wrapped = f"v1.{b64e(cid)}.sig"
            loc = f"/tracker/split?blob={quote(wrapped)}"
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        if parsed.path == "/site/lookup":
            cid = qs.get("cid", ["user-123"])[0]
            tok = token_for(cid)
            loc = f"/tracker/lookup?tok={quote(tok)}"
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        if parsed.path == "/site/random":
            garbage = secrets.token_urlsafe(10)
            loc = f"/tracker/random?noise={quote(garbage)}"
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return

        # Tracker endpoints simulate different mapping families.
        if parsed.path == "/tracker/plain":
            xid = qs.get("xid", [""])[0]
            html = f"<p>plain xid={xid}</p>"
            body = html.encode("utf-8")
            self.send_response(200)
            self._set_cookie("tid_plain", xid)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/tracker/base64":
            xid = qs.get("xid", [""])[0]
            decoded = b64d(xid) or "decode-error"
            body = f"<p>base64 xid={xid}</p>".encode("utf-8")
            self.send_response(200)
            self._set_cookie("tid_b64", decoded)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/tracker/split":
            blob = qs.get("blob", [""])[0]
            parts = blob.split(".")
            core = b64d(parts[1]) if len(parts) >= 3 else None
            decoded = core or "decode-error"
            body = f"<p>split blob={blob}</p>".encode("utf-8")
            self.send_response(200)
            self._set_cookie("tid_split", f"id::{decoded}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/tracker/lookup":
            tok = qs.get("tok", [""])[0]
            with LOOKUP_LOCK:
                resolved = LOOKUP_DB.get(tok, "lookup-miss")
            body = f"<p>lookup tok={tok}</p>".encode("utf-8")
            self.send_response(200)
            self._set_cookie("tid_lookup", f"L::{resolved}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/tracker/random":
            noise = qs.get("noise", [""])[0]
            body = f"<p>random noise={noise}</p>".encode("utf-8")
            self.send_response(200)
            self._set_cookie("tid_random", secrets.token_urlsafe(8))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self._send_html("<h1>Not found</h1>", status=HTTPStatus.NOT_FOUND)


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), LabHandler)
    print(f"Serving on http://{HOST}:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
