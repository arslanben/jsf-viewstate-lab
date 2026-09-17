#!/usr/bin/env bash
set -e

FLAG="flag{$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 28)}"
printf '%s\n' "$FLAG" > /flag.txt
chmod 444 /flag.txt

exec catalina.sh run
