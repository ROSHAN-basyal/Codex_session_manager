# Windows

This directory contains Windows-only assets and scripts.

## Prebuilt Artifact

- `dist/session_manager_V3.exe` if the older prebuilt file is still present
- `dist/codex-session-manager.exe` after a fresh Windows rebuild

The files inside `Windows/dist/` are meant to be publishable prebuilt artifacts.

## Setup

```powershell
.\Windows\scripts\setup_windows_venv.ps1
```

## Run From Source

```powershell
.\Windows\scripts\run_windows_gui.ps1
```

## Build

```powershell
.\Windows\scripts\build_windows_exe.ps1
```

After building on Windows, commit or upload:

`Windows/dist/codex-session-manager.exe`
