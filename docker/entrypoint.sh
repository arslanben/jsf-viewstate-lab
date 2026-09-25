#!/usr/bin/env bash
set -e

FLAG="flag{$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 28)}"
printf '%s\n' "$FLAG" > /flag.txt
chmod 444 /flag.txt

# leftovers from previous runs would leak stale flag values over HTTP
rm -f "$APP_HOME"/out-*.txt

# report-faithful mode: make the webroot read-only so the file-drop exfil path
# is dead and the timing side channel becomes the only way to recover output
# (see solution/README.md, "Report-faithful timing mode")
if [ "${TIMING_MODE:-0}" = "1" ]; then
  chmod -R a-w "$APP_HOME"
fi

# egress is dead: accept only loopback and replies to connections the player
# started (the host port mapping), drop everything else. Combined with the
# dead resolver from docker-compose (dns: 127.0.0.1) this reproduces the
# filtered-egress constraint of the real target
if command -v iptables >/dev/null 2>&1; then
  iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o lo -j ACCEPT
  iptables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -C OUTPUT -j DROP 2>/dev/null || iptables -A OUTPUT -j DROP
else
  echo "WARNING: iptables not available, egress filtering skipped" >&2
fi

# drop privileges: the application itself runs as the non-root service account
exec runuser -u portal -- catalina.sh run
