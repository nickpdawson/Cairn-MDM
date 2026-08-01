#!/bin/sh
# Create the cairn system user + data dir before the package installs.
set -e

if ! id cairn >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/cairn --shell /usr/sbin/nologin cairn 2>/dev/null \
      || adduser --system --home /var/lib/cairn --shell /usr/sbin/nologin cairn 2>/dev/null \
      || true
fi

install -d -o cairn -g cairn -m 0750 /var/lib/cairn
install -d -m 0750 /etc/cairn
