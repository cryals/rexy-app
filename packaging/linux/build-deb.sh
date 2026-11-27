#!/usr/bin/env bash
set -euo pipefail

VERSION="0.1.0"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
STAGE="dist/deb/r3x_${VERSION}_${ARCH}"

cargo build --release --locked -p r3x-app -p r3x-daemon -p r3x-cli

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/share/applications" "$STAGE/usr/share/metainfo" "$STAGE/usr/share/r3x/core-manifests"

install -m755 target/release/r3x-app "$STAGE/usr/bin/r3x-app"
install -m755 target/release/r3x-daemon "$STAGE/usr/bin/r3x-daemon"
install -m755 target/release/r3x "$STAGE/usr/bin/r3x"
install -m644 packaging/linux/dev.rexy.r3x.desktop "$STAGE/usr/share/applications/dev.rexy.r3x.desktop"
install -m644 packaging/linux/dev.rexy.r3x.metainfo.xml "$STAGE/usr/share/metainfo/dev.rexy.r3x.metainfo.xml"
cp -r resources/core-manifests/* "$STAGE/usr/share/r3x/core-manifests/"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: r3x
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: R3X Contributors <https://github.com/cryals/rexy-app>
Description: R3X (Rexy) Universal Multi-Core VPN & Proxy Client
EOF

mkdir -p dist
dpkg-deb --build "$STAGE" "dist/r3x_${VERSION}_${ARCH}.deb"
