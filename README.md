# JSF ViewState Deserialization Lab

A self-contained lab for a real-world bug class: unauthenticated remote code execution
through JSF client-side state saving (`javax.faces.ViewState`).

The application is a small "prepaid top-up portal" built on Mojarra (JSF 2.2) running on
Tomcat 9 with a JDK 8 runtime. The view state is Base64-encoded and GZIP-compressed but
neither encrypted nor integrity-protected, and the server deserializes it before any
authentication logic runs. The classpath contains a legacy library with a known gadget
chain.

The goal is to read `/flag.txt` from inside the container, over HTTP, as an unauthenticated
client.

> This application is intentionally vulnerable. Run it locally only. Never expose it to the
> internet or to a network you do not own.

## Requirements

- Docker Desktop (Windows, macOS) or Docker Engine with the Compose plugin (Linux)
- Python 3 (only for the solution scripts; the lab itself runs entirely in Docker)
- Roughly 1.5 GB of disk for the images; the first build downloads Tomcat, JDK 8, the
  small WAF image and a few JARs
- Internet access for the first build

## Running the lab

1. Install and start Docker. On Windows or macOS install Docker Desktop and wait until the
   status icon shows it is running. On Linux install the `docker` package and the Compose
   plugin, then make sure the daemon is up.

2. Clone the repository and start the container:

   ```
   git clone <repo-url>
   cd jsf-viewstate-lab
   docker compose up --build
   ```

   The first build takes a few minutes. Later starts reuse the cached image and are quick.

3. Open http://localhost:8080/pages/login.xhtml

4. Stop with Ctrl+C, or `docker compose down` from another terminal. Start it again with
   `docker compose up` (no `--build` needed). A new flag is generated on every start.

Other commands:

```
docker compose ps                    show the container state
docker compose logs -f portal        follow the Tomcat log
docker compose logs -f waf           follow the WAF log (shows blocked payloads)
docker compose restart portal        restart and generate a new flag
docker compose down --rmi local -v   remove container, image and volumes
```

The demo account `dealer01` / `dealer01` lets you see the authenticated dashboard. The
vulnerability does not require it.

If port 8080 is already taken, change the left side of the port mapping of the `waf`
service in `docker-compose.yml` (the WAF owns the published port; Tomcat stays internal).

### Optional: report-faithful mode (timing exfiltration)

The default solution drops a file under the web root and reads it back over HTTP. The
original engagement worked with filtered egress (DNS sinkholed, outbound TCP intercepted)
and exfiltrated command output through the **HTTP response time** instead. To replay that
path, restart the lab with the webroot locked down so the file-drop route is gone:

```
TIMING_MODE=1 docker compose up -d --force-recreate
python3 solution/timing_solver.py 'id'
```

`timing_solver.py` calibrates a baseline, verifies the response blocks on the command,
then recovers the output hex digit by digit from the response times. Details and control
measurements: `solution/README.md`, "Report-faithful timing mode".
Back to normal mode: `docker compose up -d --force-recreate` (TIMING_MODE defaults to 0).

## Objective

Recover the contents of `/flag.txt`. The file is readable by the application process, and
that process can be made to run a shell.

## Rules of engagement

- Do not read the flag with `docker exec`, `docker cp` or by inspecting the image.
- Everything else is fair game: browser dev tools, curl, Burp, ysoserial, custom scripts.

## What is in the box

- Tomcat 9 (`tomcat:9-jdk8-temurin`)
- Mojarra 2.2.20 (`javax.faces-2.2.20.jar`)
- A `WEB-INF/lib` directory worth enumerating (the gadget dependency is **not**
  listed here on purpose — finding it is part of the exercise)
- Client-side state saving with encryption disabled (see `app/src/main/webapp/WEB-INF/web.xml`)
- The application process runs as a **non-root service account** (uid 1001), like a
  constrained account on a real deployment — check it once you have command execution
- A reverse proxy / **WAF in front of Tomcat**: everything on port 8080 goes through it,
  and it enforces a serialization signature rule (part of the exercise — see
  `solution/README.md`)
- Container capped at 2 vCPU and 2 GB RAM
- Demo credentials for the UI: `dealer01` / `dealer01`

## Hints

`HINTS.md` contains progressive hints. Read them one at a time.

## Solution

`solution/README.md` is the full walkthrough; `solution/solve.py` and
`solution/timing_solver.py` automate the exploit (default and timing mode), and
`solution/oracle.py` reproduces the discovery probes. Do not open them until you have
tried the lab yourself.

## Background

When `javax.faces.STATE_SAVING_METHOD` is set to `client`, JSF serializes the state of the
view and ships it to the browser in a hidden `javax.faces.ViewState` field. Every postback
sends the value back and the server deserializes it to rebuild the component tree.

The format used by Mojarra is `Base64(GZIP(serialized object))`. If that value is not
encrypted and the classpath contains a usable gadget chain, an attacker can replace the
field with an arbitrary serialized object and get code execution during `readObject()`.
In the JSF lifecycle this happens while the view is restored, before the application action
(login, captcha validation, ...) is invoked.

Two configuration mistakes make this lab vulnerable:

- client-side state saving enabled (`javax.faces.STATE_SAVING_METHOD=client`)
- state encryption disabled (`com.sun.faces.disableClientStateEncryption=true`)

Add a gadget library (commons-beanutils / commons-collections) and the result is
pre-authentication remote code execution.

## Fixing it in real applications

- Use server-side state saving, which is the specification default. Do not switch to
  client-side state saving without a concrete requirement.
- If client-side state saving is required, never disable encryption. On Mojarra 2.2+ leave
  `com.sun.faces.disableClientStateEncryption` at its default; for clustered deployments
  configure a stable `jsf/ClientSideSecretKey` instead of turning encryption off.
- Remove unused gadget libraries (commons-beanutils, commons-collections and friends) from
  the application classpath. Blocklists of "bad classes" are not a durable control.
- Where the runtime supports it, apply a JVM-wide deserialization filter as defense in
  depth.
- A WAF rule that looks for serialized blobs in `javax.faces.ViewState` is a mitigation,
  not a fix; the encoding is trivial to vary.
- Keep the JSF implementation patched. Older Mojarra branches shipped with no default
  view state encryption at all.

## References

- Synacktiv, "JSF ViewState upside-down" (2013) — format details and ViewState tampering
- Alphabot Security, "Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities"
- HackTricks, "Java JSF ViewState (.faces) Deserialization"
- ysoserial, `CommonsBeanutils1` payload

## License

MIT, see `LICENSE`.
