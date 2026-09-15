#!/bin/sh
# Read via stdin, not a command-line argument/history entry.
set -eu
DIR=/opt/etc/hotwatcher
[ -d "$DIR" ] && [ ! -L "$DIR" ] || { echo 'Run install.sh first.' >&2; exit 1; }
TMP=$(mktemp "$DIR/.subscription.XXXXXX")
ECHO_OFF=0
cleanup() { [ "$ECHO_OFF" = 0 ] || stty echo; rm -f "$TMP"; }
trap cleanup EXIT HUP INT TERM
printf 'Paste the HTTPS subscription URL and press Enter: '
if [ -t 0 ]; then stty -echo; ECHO_OFF=1; fi
IFS= read -r URL
if [ "$ECHO_OFF" = 1 ]; then stty echo; ECHO_OFF=0; fi
printf '\n'
case "$URL" in https://*) ;; *) echo 'HTTPS URL required.' >&2; exit 1 ;; esac
chmod 600 "$TMP"
printf '%s\n' "$URL" > "$TMP"
unset URL
mv -f "$TMP" "$DIR/subscription.url"
echo 'Saved privately. Run hotwatcher plan to validate format without changing Xray.'
