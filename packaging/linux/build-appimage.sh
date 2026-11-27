#!/usr/bin/env bash
set -euo pipefail

VERSION="0.1.0"
ARCH="$(uname -m)"
APPDIR="dist/AppDir"

cargo build --release --locked -p r3x-app -p r3x-daemon -p r3x-cli

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/metainfo"

install -m755 target/release/r3x-app "$APPDIR/usr/bin/r3x-app"
install -m755 target/release/r3x-daemon "$APPDIR/usr/bin/r3x-daemon"
install -m755 target/release/r3x "$APPDIR/usr/bin/r3x"
install -m644 packaging/linux/dev.rexy.r3x.desktop "$APPDIR/dev.rexy.r3x.desktop"
install -m644 packaging/linux/dev.rexy.r3x.desktop "$APPDIR/usr/share/applications/dev.rexy.r3x.desktop"
install -m644 ui/assets/icons/shield.svg "$APPDIR/dev.rexy.r3x.svg"

cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/r3x-app" "$@"
EOF
chmod +x "$APPDIR/AppRun"

if command -v appimagetool >/dev/null 2>&1; then
  ARCH="$ARCH" appimagetool "$APPDIR" "dist/R3X-${VERSION}-${ARCH}.AppImage"
else
  tar -czf "dist/r3x-${VERSION}-linux-${ARCH}-portable.tar.gz" -C "$APPDIR" .
fi
