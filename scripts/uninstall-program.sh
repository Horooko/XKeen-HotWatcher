#!/bin/sh
# Removes only program/autostart. Runtime and data are intentionally retained.
set -eu
rm -f /opt/etc/hotwatcher/enabled
/opt/etc/init.d/S99hotwatcher stop
rm -f /opt/etc/init.d/S99hotwatcher /opt/sbin/hotwatcher
echo 'Hot Watcher program removed. Xray is still running.'
echo 'Configuration, API fragment, state and subscription credentials are retained.'
echo 'For a full migration rollback, follow docs/ROLLBACK.md outside a game.'
