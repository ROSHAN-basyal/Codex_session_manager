#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/Linux/dist"
APP_NAME="codex-session-manager"
APPDIR="$OUTPUT_DIR/AppDir"
APPIMAGE_NAME="Codex-Session-Manager.AppImage"
BINARY_PATH="$OUTPUT_DIR/$APP_NAME"
APPIMAGETOOL_BIN="${APPIMAGETOOL:-appimagetool}"

if [ ! -x "$BINARY_PATH" ]; then
  echo "Linux binary not found at $BINARY_PATH"
  echo "Building it first..."
  "$ROOT_DIR/Linux/scripts/build_linux_binary.sh"
fi

if ! command -v "$APPIMAGETOOL_BIN" >/dev/null 2>&1; then
  echo "appimagetool is not installed or not on PATH."
  echo "Set APPIMAGETOOL=/path/to/appimagetool or install it in the Linux VM."
  exit 1
fi

rm -rf "$APPDIR"
mkdir -p \
  "$APPDIR/usr/bin" \
  "$APPDIR/usr/share/applications" \
  "$APPDIR/usr/share/icons/hicolor/scalable/apps"

cp "$BINARY_PATH" "$APPDIR/usr/bin/$APP_NAME"
cp "$ROOT_DIR/Linux/packaging/linux/$APP_NAME.desktop" "$APPDIR/$APP_NAME.desktop"
cp "$ROOT_DIR/Linux/packaging/linux/$APP_NAME.desktop" "$APPDIR/usr/share/applications/$APP_NAME.desktop"
cp "$ROOT_DIR/Linux/packaging/linux/$APP_NAME.svg" "$APPDIR/$APP_NAME.svg"
cp "$ROOT_DIR/Linux/packaging/linux/$APP_NAME.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/$APP_NAME.svg"
ln -sf "usr/bin/$APP_NAME" "$APPDIR/AppRun"

"$APPIMAGETOOL_BIN" "$APPDIR" "$OUTPUT_DIR/$APPIMAGE_NAME"
rm -rf "$APPDIR"

echo
echo "AppImage complete:"
echo "  $OUTPUT_DIR/$APPIMAGE_NAME"
echo
echo "Users can run it with:"
echo "  chmod +x $APPIMAGE_NAME"
echo "  ./$APPIMAGE_NAME"
