#!/bin/sh
# Adds a localhost-only API fragment, with no restart.
set -eu
DIR=/opt/etc/xray/configs
FILE="$DIR/07_hotwatcher_api.json"
[ -d "$DIR" ] || { echo 'Xray config directory not found.' >&2; exit 1; }
if [ -e "$FILE" ]; then echo 'API fragment already exists; left unchanged.'; exit 0; fi
for f in "$DIR"/*.json; do
 if grep -q '"api"[[:space:]]*:' "$f"; then
  echo 'An API object already exists. Do not create a second one.' >&2
  echo 'Merge HandlerService and RoutingService into it; use a loopback listen address.' >&2
  echo 'See docs/INSTALLATION.md and set api_address accordingly.' >&2
  exit 1
 fi
done
umask 077
TMP=$(mktemp "$DIR/.api.XXXXXX")
trap 'rm -f "$TMP"' EXIT HUP INT TERM
cat > "$TMP" <<'JSON'
{
  "api": {
    "tag": "hotwatcher-api",
    "listen": "127.0.0.1:10085",
    "services": ["HandlerService", "RoutingService"]
  }
}
JSON
mv "$TMP" "$FILE"
echo 'API fragment written. Production Xray has NOT been restarted.'
echo 'Outside a game: run xkeen -xtest, then one deliberate xkeen -restart.'
echo 'If startup fails, remove only 07_hotwatcher_api.json and restore previous startup.'
