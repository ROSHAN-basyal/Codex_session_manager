#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

echo "Project root: $ROOT_DIR"

if ! command -v python >/dev/null 2>&1; then
  echo "Python is not installed or not on PATH."
  echo "On Arch/EndeavourOS inside your Linux VM, install it with:"
  echo "  sudo pacman -S python"
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment at $VENV_DIR"
  python -m venv "$VENV_DIR"
else
  echo "Virtual environment already exists at $VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"

echo "Checking Tk support in the virtual environment"
if ! "$VENV_PYTHON" - <<'PY'
import tkinter  # noqa: F401
print("Tkinter import: OK")
PY
then
  echo
  echo "Tk support is missing from the underlying system Python runtime."
  echo "Install the required Linux packages inside your VM, then recreate the venv if needed:"
  echo "  sudo pacman -S tk xdg-utils"
  echo
  echo "Install one terminal emulator if your desktop does not already provide one:"
  echo "  sudo pacman -S gnome-terminal"
  echo "  sudo pacman -S konsole"
  echo "  sudo pacman -S kitty"
  exit 1
fi

if ! command -v xdg-open >/dev/null 2>&1; then
  echo "Missing xdg-open. Install xdg-utils inside the VM:"
  echo "  sudo pacman -S xdg-utils"
  exit 1
fi

if ! command -v codex >/dev/null 2>&1; then
  echo "Warning: \`codex\` is not on PATH. The GUI will open, but Resume will not work until Codex CLI is installed."
fi

for terminal in x-terminal-emulator gnome-terminal konsole xfce4-terminal tilix alacritty kitty xterm; do
  if command -v "$terminal" >/dev/null 2>&1; then
    echo "Detected terminal emulator: $terminal"
    break
  fi
done

if ! command -v x-terminal-emulator >/dev/null 2>&1 \
  && ! command -v gnome-terminal >/dev/null 2>&1 \
  && ! command -v konsole >/dev/null 2>&1 \
  && ! command -v xfce4-terminal >/dev/null 2>&1 \
  && ! command -v tilix >/dev/null 2>&1 \
  && ! command -v alacritty >/dev/null 2>&1 \
  && ! command -v kitty >/dev/null 2>&1 \
  && ! command -v xterm >/dev/null 2>&1; then
  echo "No supported terminal emulator detected."
  echo "Install one inside the VM, for example:"
  echo "  sudo pacman -S kitty"
  exit 1
fi

echo
echo "Linux GUI environment looks ready."
echo "Launch the app with:"
echo "  ./scripts/run_linux_gui.sh"
