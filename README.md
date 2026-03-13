# Codex Session Browser

This repository is now split into:

- root `/`: shared application code and shared build requirements
- `/Linux`: Linux-only scripts, packaging assets, and Linux distributables
- `/Windows`: Windows-only scripts and Windows distributables

The shared desktop app entrypoint remains [codex_session_manager.py](/home/rsnb/Documents/My_projects/Codex_session_manager/codex_session_manager.py).

## Repository Layout

Shared files in `/`:

- `codex_session_manager.py`
- `guide_for_linux.md`
- `guide_for_windows.md`
- `README.md`
- `requirements-build.txt`

Linux-only files in `/Linux`:

- `Linux/scripts/`
- `Linux/packaging/linux/`
- `Linux/dist/`

Windows-only files in `/Windows`:

- `Windows/scripts/`
- `Windows/dist/`

## Run From Source

Shared source run:

```bash
python codex_session_manager.py
```

Optional sessions override:

```bash
python codex_session_manager.py --sessions-dir "$HOME/.codex/sessions"
```

Startup order:

1. `--sessions-dir`, if provided
2. previously saved app config
3. default `~/.codex/sessions`, if it exists
4. GUI folder picker

## Linux

Linux-specific setup and build files live under [`Linux/`](/home/rsnb/Documents/My_projects/Codex_session_manager/Linux).

Setup in a Linux VM:

```bash
python -m venv .venv
./Linux/scripts/setup_linux_venv.sh
./Linux/scripts/run_linux_gui.sh
```

Build Linux binary:

```bash
.venv/bin/pip install -r requirements-build.txt
./Linux/scripts/build_linux_binary.sh
```

Build Linux AppImage:

```bash
./Linux/scripts/build_linux_appimage.sh
```

Linux outputs:

- `Linux/dist/codex-session-manager`
- `Linux/dist/Codex-Session-Manager.AppImage`

The `Linux/dist/` directory is intended to be committed and pushed so users can download prebuilt Linux artifacts directly from GitHub.

For Arch / EndeavourOS in the Linux VM:

```bash
sudo pacman -S python tk xdg-utils
```

Recommended Linux terminal emulators:

- `gnome-terminal`
- `konsole`
- `kitty`
- `xfce4-terminal`
- `tilix`
- `alacritty`
- `xterm`

## Windows

Windows-specific setup and build files live under [`Windows/`](/home/rsnb/Documents/My_projects/Codex_session_manager/Windows).

Setup a Windows venv:

```powershell
.\Windows\scripts\setup_windows_venv.ps1
```

Run from source on Windows:

```powershell
.\Windows\scripts\run_windows_gui.ps1
```

Build the Windows executable:

```powershell
.\Windows\scripts\build_windows_exe.ps1
```

Windows output:

- `Windows/dist/codex-session-manager.exe`

The `Windows/dist/` directory is intended to be committed and pushed so users can download prebuilt Windows artifacts directly from GitHub.

The Windows build script is configured to generate `Windows/dist/codex-session-manager.exe` when run on a Windows machine. Until that new build is generated on Windows, the directory may still contain the older prebuilt executable.

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

Detailed guides:

- [guide_for_linux.md](/home/rsnb/Documents/My_projects/Codex_session_manager/guide_for_linux.md)
- [guide_for_windows.md](/home/rsnb/Documents/My_projects/Codex_session_manager/guide_for_windows.md)
