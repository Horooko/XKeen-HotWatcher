#!/bin/sh
set -eu
umask 077
FILE="/tmp/hotwatcher-support-$(date +%Y%m%d-%H%M%S).txt"
{
 echo '=== LOCAL TIME ==='; date
 echo '=== ARCH ==='; uname -m
 echo '=== VERSION ==='; /opt/sbin/hotwatcher version
 echo '=== STATUS ==='; /opt/sbin/hotwatcher status || true
 echo '=== DOCTOR ==='; /opt/sbin/hotwatcher doctor || true
 echo '=== RECENT SANITIZED EVENTS ==='; tail -n 60 /opt/var/lib/hotwatcher/events.jsonl 2>/dev/null || true
} > "$FILE" 2>&1
printf 'Report: %s\n' "$FILE"
echo 'Review before sharing. No raw subscription, crontab, Xray config or API lso output was included.'
