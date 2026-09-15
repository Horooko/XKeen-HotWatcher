#!/bin/sh
# Preserve all other jobs, and keep the secret-bearing original crontab private.
set -eu
STATE=/opt/var/lib/hotwatcher
[ -d "$STATE" ] && [ ! -L "$STATE" ] || { echo 'Run install.sh first.' >&2; exit 1; }
umask 077
BACKUP="$STATE/crontab-before-hotwatcher-$(date +%Y%m%d-%H%M%S).txt"
TMP=$(mktemp "$STATE/.cron.XXXXXX")
trap 'rm -f "$TMP"' EXIT HUP INT TERM
if ! crontab -l > "$BACKUP"; then
 echo 'Could not read current crontab. Nothing changed.' >&2
 exit 1
fi
awk 'index($0,"xkeen-subscription-watcher") == 0' "$BACKUP" > "$TMP"
crontab "$TMP"
echo "Old watcher jobs disabled. Private backup: $BACKUP"
echo 'The old binary and other cron jobs were kept. Do not run both watchers.'
echo 'Review other scheduled restarts separately; Hot Watcher cannot prevent them.'
