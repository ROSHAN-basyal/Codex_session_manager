#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
  echo "Virtual environment not found at $VENV_DIR"
  echo "Run ./scripts/setup_linux_venv.sh first."
  exit 1
fi

if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  echo "No graphical desktop session detected."
  echo "Start this from a Linux desktop session with DISPLAY or WAYLAND_DISPLAY set."
  exit 1
fi

exec "$VENV_DIR/bin/python" "$ROOT_DIR/codex_session_manager.py" "$@"
