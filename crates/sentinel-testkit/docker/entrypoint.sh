#!/bin/sh
set -eu
# Registered health check target: http://127.0.0.1:8080/health
su -s /bin/sh sentinel -c 'cd /srv/www && exec python3 -m http.server 8080 --bind 127.0.0.1' >/dev/null 2>&1 &
exec /usr/sbin/sshd -D -e
