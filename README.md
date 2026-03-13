# Codex Session Browser

This is a modern GUI for browsing local Codex sessions, editing titles, opening session folders/logs, and resuming a session in a shell. The interface is built with **CustomTkinter** and features a sleek, system-adaptive dark/light theme.

The project started as a Windows-only utility. The source now also supports Linux desktop environments, including Arch/EndeavourOS, as long as Tk and a terminal emulator are installed.

## Run From Source

```bash
python codex_session_manager.py
```

Optional override for a specific sessions directory:

```bash
python codex_session_manager.py --sessions-dir "$HOME/.codex/sessions"
```

Startup order:

1. `--sessions-dir`, if provided
2. previously saved app config
3. default `~/.codex/sessions`, if it exists
4. GUI folder picker

## Linux VM Setup

Inside your Linux VM:

```bash
python -m venv .venv
./scripts/setup_linux_venv.sh
./scripts/run_linux_gui.sh
```

The setup script validates:

- the project-local virtual environment
- CustomTkinter installation (auto-installed via pip)
- Tk availability in that venv
- `xdg-open`
- a supported terminal emulator
- whether `codex` is on `PATH`

If Tk is missing, the script stops with the exact `pacman` packages you need to install in the VM.

## Linux Requirements

This app needs:

- Python 3
- Tk support for Python
- CustomTkinter (auto-installed by the setup script via `pip install customtkinter`)
- a graphical desktop session (`DISPLAY` or `WAYLAND_DISPLAY`)
- a terminal emulator for Resume / Open CWD in Terminal
- `xdg-open` from `xdg-utils` for opening logs and folders

For Arch / EndeavourOS, install the system packages in your Linux VM:

```bash
sudo pacman -S python tk xdg-utils
```

Recommended terminal emulators on Linux:

- `gnome-terminal`
- `konsole`
- `kitty`
- `xfce4-terminal`
- `tilix`
- `alacritty`
- `xterm`

The app does not install Tk through `pip`; Tk is an OS package. CustomTkinter is installed via pip in the virtual environment.

## Windows Run

The existing Windows build artifact is still included:

```text
dist_v3/session_manager_V3.exe
```

## Build

Windows example:

```powershell
python -m PyInstaller --onefile --noconsole --name session_manager_V3 codex_session_manager.py
```

Linux example:

```bash
python -m PyInstaller --onefile --windowed --name session_manager_linux codex_session_manager.py
```

## What The App Stores

- title overrides: `<sessions_dir>/session mananger/titles/session_titles.json`
- CLI preference: `<sessions_dir>/session mananger/settings.json`
- app config on Linux: `${XDG_CONFIG_HOME:-~/.config}/.codex_session_manager/config.json`
- app config on Windows: `%APPDATA%\.codex_session_manager\config.json`

The `session mananger` directory name is kept as-is for compatibility with the existing app data.

## Features

- Search by title, cwd, session id, or file path
- Sort by Title, Created, or Updated
- Resume the selected session with `codex resume <session_id>`
- Open the session working directory
- Open the session working directory in the selected shell
- Open the raw rollout log
- Save and reset custom titles

## GUI Layout

- top bar: search, clear, search button, refresh button
- center: session table
- right panel: title editor, metadata, shell selector, actions

See `GUIDE.md` for the day-to-day usage flow.
