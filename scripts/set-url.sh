#!/bin/sh
# Read via stdin, not a command-line argument/history entry.
set -eu
[ -x /opt/sbin/hotwatcher ] || { echo 'Run install.sh first.' >&2; exit 1; }
if [ ! -f /opt/etc/xray/configs/07_hotwatcher_api.json ]; then
 sh "$(dirname "$0")/setup-api.sh"
fi
ECHO_OFF=0
cleanup() { [ "$ECHO_OFF" = 0 ] || stty echo; unset URL; }
trap cleanup EXIT HUP INT TERM
printf 'Paste the HTTPS subscription URL and press Enter: '
if [ -t 0 ]; then stty -echo; ECHO_OFF=1; fi
IFS= read -r URL
if [ "$ECHO_OFF" = 1 ]; then stty echo; ECHO_OFF=0; fi
printf '\n'
case "$URL" in https://*) ;; *) echo 'HTTPS URL required.' >&2; exit 1 ;; esac
printf '%s\n' "$URL" | /opt/sbin/hotwatcher url set
unset URL
echo 'Saved in private 07_hotwatcher_api.json. Run hotwatcher plan to validate without changing Xray.'
