#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
PYTHON_BIN="$VENV_DIR/bin/python"
PYINSTALLER_BIN="$VENV_DIR/bin/pyinstaller"
OUTPUT_DIR="$ROOT_DIR/Linux/dist"
APP_NAME="codex-session-manager"
BUILD_DIR="$ROOT_DIR/build/$APP_NAME"
SPEC_FILE="$ROOT_DIR/$APP_NAME.spec"

if [ ! -d "$VENV_DIR" ]; then
  echo "Virtual environment not found at $VENV_DIR"
  echo "Run ./Linux/scripts/setup_linux_venv.sh first."
  exit 1
fi

if ! "$PYTHON_BIN" - <<'PY'
import tkinter  # noqa: F401
PY
then
  echo "Tk is not available in the current Python runtime."
  echo "Inside your Linux VM, install the required system packages first:"
  echo "  sudo pacman -S tk xdg-utils"
  exit 1
fi

if [ ! -x "$PYINSTALLER_BIN" ]; then
  echo "PyInstaller is not installed in $VENV_DIR"
  echo "Install the build dependency inside the venv with:"
  echo "  $VENV_DIR/bin/pip install -r requirements-build.txt"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
rm -rf "$BUILD_DIR" "$OUTPUT_DIR/AppDir"
rm -f "$OUTPUT_DIR/$APP_NAME" "$OUTPUT_DIR/Codex-Session-Manager.AppImage" "$SPEC_FILE"

"$PYINSTALLER_BIN" \
  --noconfirm \
  --clean \
  --onefile \
  --windowed \
  --name "$APP_NAME" \
  --distpath "$OUTPUT_DIR" \
  "$ROOT_DIR/codex_session_manager.py"

rm -rf "$BUILD_DIR" "$SPEC_FILE"
rmdir "$ROOT_DIR/build" 2>/dev/null || true

echo
echo "Build complete:"
echo "  $OUTPUT_DIR/$APP_NAME"
echo
echo "Important:"
echo "  This is a Linux binary, not a Windows .exe."
echo "  For best compatibility, build it on the oldest Linux distro you plan to support."
echo "  If you want a more portable single-file Linux distribution format, package the app as an AppImage."
