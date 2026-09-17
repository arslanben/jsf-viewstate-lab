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
- Roughly 1.5 GB of disk for the image; the first build downloads Tomcat, JDK 8 and a few JARs
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
docker compose restart portal        restart and generate a new flag
docker compose down --rmi local -v   remove container, image and volumes
```

The demo account `dealer01` / `dealer01` lets you see the authenticated dashboard. The
vulnerability does not require it.

If port 8080 is already taken, change the left side of the port mapping in
`docker-compose.yml`.

## Objective

Recover the contents of `/flag.txt`. The file is readable by the application process, and
that process can be made to run a shell.

## Rules of engagement

- Do not read the flag with `docker exec`, `docker cp` or by inspecting the image.
- Everything else is fair game: browser dev tools, curl, Burp, ysoserial, custom scripts.

## What is in the box

- Tomcat 9 (`tomcat:9-jdk8-temurin`)
- Mojarra 2.2.20 (`javax.faces-2.2.20.jar`)
- commons-beanutils 1.9.2, commons-collections 3.1, commons-logging 1.2
- Client-side state saving with encryption disabled (see `app/src/main/webapp/WEB-INF/web.xml`)
- Container capped at 2 vCPU and 2 GB RAM
- Demo credentials for the UI: `dealer01` / `dealer01`

## Hints

`HINTS.md` contains progressive hints. Read them one at a time.

## Solution

`solution/README.md` is the full walkthrough and `solution/solve.py` automates the exploit.
Do not open them until you have tried the lab yourself.

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
