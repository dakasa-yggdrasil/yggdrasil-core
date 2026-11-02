#!/bin/sh
# Check the actual ELF executables, not just an image's platform label.
set -eu

platform=$1
root=${2%/}
case "$platform" in
    linux/amd64) machine=62 ;;
    linux/arm64) machine=183 ;;
    *) echo "Unsupported target platform: $platform" >&2; exit 1 ;;
esac

for path in app/yggdrasil-core app/goose app/yggdrasil-bootstrap app/yggdrasil-bootstrap-admin usr/local/bin/kubectl; do
    binary="$root/$path"
    magic=$(od -An -tx1 -N4 "$binary" | tr -d ' \n')
    actual_machine=$(od -An -tu2 -j18 -N2 "$binary" | tr -d ' \n')
    if [ "$magic" != 7f454c46 ] || [ "$actual_machine" != "$machine" ]; then
        echo "Invalid ELF architecture for $platform: $path (magic=$magic, e_machine=$actual_machine)" >&2
        exit 1
    fi
done
