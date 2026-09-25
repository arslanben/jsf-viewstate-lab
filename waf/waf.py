#!/usr/bin/env python3
"""
Reverse proxy with an F5-ASM-like serialization rule for the JSF ViewState lab.

It sits between the player and Tomcat and enforces the same class of rule the
real target's F5 ASM did (see ../solution/README.md, "The WAF in front"):

    a serialized payload that references
    com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
    is only allowed when it carries the standard HotSpot serialVersionUID.

Anything else — including the deliberate error probes from the oracle step —
is passed through untouched, so the deserialization error oracle still works.
"""

import base64
import gzip
import http.client
import random
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

BACKEND_HOST = "portal"
BACKEND_PORT = 8080
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
MAX_BODY = 4 * 1024 * 1024
BACKEND_TIMEOUT = 300  # seconds; long enough for timing-mode responses

TEMPLATES_IMPL = b"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"
STANDARD_SUID = bytes.fromhex("09574fc16eacab33")

HOP_BY_HOP = {
    "connection", "keep-alive", "transfer-encoding", "upgrade",
    "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "content-length", "host",
}

BLOCK_PAGE = """<!DOCTYPE html>
<html><head><title>Request Rejected</title></head>
<body>
<h2>Request Rejected</h2>
<p>We blocked your request. Reference #<b>%(ref)s</b></p>
<p>Violation: java-serialization-signature (security policy: ASM-DEFAULT)</p>
<hr><p>BigIP-ASM</p>
</body></html>
"""


def extract_viewstate(body):
    """Return the javax.faces.ViewState value from a urlencoded form body."""
    try:
        form = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
    except Exception:
        return None
    values = form.get("javax.faces.ViewState")
    return values[0] if values else None


def asm_rule(viewstate_b64):
    """Return a block reason if the payload violates the SUID rule, else None."""
    try:
        raw = base64.b64decode(viewstate_b64, validate=False)
        data = gzip.decompress(raw)          # non-gzip input -> None (oracle probes pass)
    except Exception:
        return None
    i = data.find(TEMPLATES_IMPL)
    if i < 0:
        return None
    suid = data[i + len(TEMPLATES_IMPL): i + len(TEMPLATES_IMPL) + 8]
    if suid != STANDARD_SUID:
        return "custom TemplatesImpl serialVersionUID %s" % suid.hex()
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        n = int(length)
        if n > MAX_BODY:
            raise ValueError("body too large")
        return self.rfile.read(n)

    def _handle(self, method):
        try:
            body = self._read_body() if method in ("POST", "PUT", "PATCH") else b""
        except ValueError:
            self.send_error(413)
            return

        content_type = self.headers.get("Content-Type", "")
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            viewstate = extract_viewstate(body)
            if viewstate is not None:
                reason = asm_rule(viewstate)
                if reason is not None:
                    ref = "%08x" % random.getrandbits(32)
                    page = (BLOCK_PAGE % {"ref": ref}).encode()
                    self.send_response(403)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(page)))
                    self.send_header("X-Block-Reason", "asm-suid-rule")
                    self.end_headers()
                    self.wfile.write(page)
                    self.log_message("BLOCKED asm-suid-rule (%s)", reason)
                    return

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP_BY_HOP}
        headers["Host"] = "%s:%d" % (BACKEND_HOST, BACKEND_PORT)

        try:
            conn = http.client.HTTPConnection(
                BACKEND_HOST, BACKEND_PORT, timeout=BACKEND_TIMEOUT)
            conn.request(method, self.path, body=body or None, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            status = resp.status
            resp_headers = resp.getheaders()
            conn.close()
        except Exception as exc:
            page = ("upstream unavailable: %s" % exc).encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return

        ctype = dict((k.lower(), v) for k, v in resp_headers).get("content-type", "")
        has_ts = any(k.lower() == "set-cookie" and v.startswith("TS")
                     for k, v in resp_headers)

        self.send_response_only(status)
        for k, v in resp_headers:
            if k.lower() in HOP_BY_HOP:
                continue
            self.send_header(k, v)
        if "text/html" in ctype and not has_ts:
            self.send_header(
                "Set-Cookie",
                "TS%04x=%016x; path=/" % (random.getrandbits(16),
                                           random.getrandbits(64)))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(data)
        self.log_message("%s %s -> %s", method, self.path, status)

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_OPTIONS(self):
        self._handle("OPTIONS")


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.daemon_threads = True
    print("[waf] listening on %s:%d -> %s:%d (asm-suid-rule active)"
          % (LISTEN_HOST, LISTEN_PORT, BACKEND_HOST, BACKEND_PORT))
    server.serve_forever()


if __name__ == "__main__":
    main()
