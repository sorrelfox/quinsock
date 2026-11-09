#!/bin/bash
# Runs inside a build container (see build.sh). /src is the read-only source tree,
# /build/target a per-distro cache volume, /out the host's dist/<target> directory.
set -euo pipefail

mkdir -p /build
tar -C /src --exclude=./target --exclude=./dist --exclude=./.git -cf - . | tar -C /build -xf -
cd /build

cargo build --release --locked

case "$KIND" in
    rpm) cargo generate-rpm --set-metadata "release = \"$RELEASE\"" --output /out/ ;;
    deb) cargo deb --no-build --deb-revision "$RELEASE" --output /out/ ;;
    *) echo "unknown package kind: $KIND" >&2; exit 1 ;;
esac
