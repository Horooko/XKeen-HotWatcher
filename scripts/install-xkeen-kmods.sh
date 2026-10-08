#!/bin/sh
# Install a persistent module loader before XKeen's S05 init script.
set -eu
source_file=/opt/tmp/S04xkeen-netfilter-modules
target_file=/opt/etc/init.d/S04xkeen-netfilter-modules

if [ ! -r "$source_file" ]; then
    echo "Missing source: $source_file" >&2
    exit 1
fi
if [ -e "$target_file" ]; then
    if cmp -s "$source_file" "$target_file"; then
        echo 'Module loader is already installed.'
    else
        echo "Existing file differs; it was not overwritten: $target_file" >&2
        exit 1
    fi
else
    cp "$source_file" "$target_file"
    echo "Installed: $target_file"
fi
chmod 755 "$target_file"

echo 'Startup order: S04xkeen-netfilter-modules, then S05xkeen.'
echo 'No firewall rules, Xray process, or DNS settings were changed.'
