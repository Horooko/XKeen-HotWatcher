#!/bin/sh
set -eu
/opt/sbin/hotwatcher doctor
/opt/sbin/hotwatcher status
[ -f /opt/var/lib/hotwatcher/state.json ] || { echo 'Run hotwatcher adopt first.' >&2; exit 1; }
[ ! -f /opt/var/lib/hotwatcher/pending.json ] || { echo 'Resolve pending transaction first.' >&2; exit 1; }
(umask 077; : > /opt/etc/hotwatcher/enabled)
/opt/etc/init.d/S99hotwatcher start
