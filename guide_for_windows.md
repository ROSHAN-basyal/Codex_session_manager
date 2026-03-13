# Windows Guide

## Purpose

This guide explains, step by step, how to set up, run, use, and build the Codex Session Browser on Windows.

The repository is organized like this:

- shared application code is in the repository root
- Linux-only files are in `Linux/`
- Windows-only files are in `Windows/`

The shared GUI entrypoint is:

`codex_session_manager.py`

## What The App Does

The app reads local Codex session files from your `.codex\sessions` directory, shows them in a GUI, lets you search and rename them, and can resume a session by launching:

`codex resume <session_id>`

## Windows Requirements

You need all of the following:

- Windows Python installed and available on `PATH`
- Python installed with Tcl/Tk support
- PowerShell available
- the `codex` command available on `PATH` if you want Resume to work

The app can launch these Windows shell types when they are available:

- PowerShell 7
- Windows PowerShell
- Command Prompt
- Git Bash

## Step 1: Open PowerShell In The Project Folder

Open PowerShell and change into the project folder:

```powershell
cd C:\path\to\Codex_session_manager
```

Replace that path with the real path to your clone.

## Step 2: Create The Python Virtual Environment

Run:

```powershell
python -m venv .venv
```

This creates the virtual environment in:

`.venv`

## Step 3: Activate The Virtual Environment

From PowerShell, run:

```powershell
.\.venv\Scripts\Activate.ps1
```

When activation succeeds, the prompt usually shows:

`(.venv)`

## Step 4: Run The Windows Setup Script

Run:

```powershell
.\Windows\scripts\setup_windows_venv.ps1
```

This script:

- creates `.venv` if it does not already exist
- installs `customtkinter`
- checks that both `tkinter` and `customtkinter` can be imported

If the script reports that Tkinter cannot be loaded, reinstall Python on Windows and make sure Tcl/Tk support is included.

## Step 5: Run The App From Source

To run the app from source:

```powershell
.\Windows\scripts\run_windows_gui.ps1
```

You can also pass optional overrides:

```powershell
.\Windows\scripts\run_windows_gui.ps1 -SessionsDir "C:\Users\<You>\.codex\sessions"
```

The PowerShell launcher runs the shared root file:

`codex_session_manager.py`

## Step 6: First Launch Behavior

When the app starts, it resolves the sessions directory in this order:

1. the path passed through `--sessions-dir`
2. the saved app config
3. the default `%USERPROFILE%\.codex\sessions`, if it exists
4. a folder picker

If the default sessions path exists, the app uses it automatically.

If it does not exist, the app opens a folder picker. You can select:

- the `.codex` folder
- the `sessions` folder
- any subfolder inside `.codex`

The app resolves the correct sessions directory from that selection.

## Step 7: Basic UI Usage

### Search

Use the search field to filter by:

- title
- cwd
- session ID
- file path

You can:

- press `Enter`
- click `Search`
- click `Clear`

### Sessions List

The left panel shows the sessions list.

Each row includes:

- a resume glyph before the session title
- created timestamp
- updated timestamp
- cwd
- short session ID

You can:

- click a row to load its details
- double-click a row to resume it
- click the small resume glyph area at the start of the title cell to resume that row directly

### Session Details

The right panel contains:

- title field
- session ID
- created timestamp
- updated timestamp
- cwd
- log file path
- CLI shell dropdown
- action buttons

The details panel is scrollable, so smaller windows still allow the user to reach the lower controls.

### Sorting

You can sort by:

- Title
- Created
- Updated

Click the column header once to sort.

Click it again to reverse the direction.

## Step 8: Resume A Session

To resume a session:

1. select a session
2. choose a CLI shell if needed
3. click `Resume Session`

The app opens a new shell and runs:

`codex resume <session_id>`

This only works if `codex` is on your Windows `PATH`.

## Step 9: Open Files And Folders

The available actions are:

- `Copy ID`
- `Open CWD`
- `CWD in Terminal`
- `Open Log`

On Windows:

- folders and files are opened through the Windows shell
- terminals are opened using the selected shell type

## Step 10: Build A Fresh Windows Executable

To build a new Windows `.exe`, first activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then run:

```powershell
.\Windows\scripts\build_windows_exe.ps1
```

That script will install `PyInstaller` into `.venv` if needed and then build:

`Windows\dist\codex-session-manager.exe`

That output file is intended to stay in `Windows\dist\` so it can be committed or uploaded to GitHub as a prebuilt Windows executable.

## Existing Windows Binary

The repository may contain an older prebuilt Windows executable in:

`Windows\dist\session_manager_V3.exe`

If you want a fresh executable with the new naming, build it on Windows using the PowerShell build script above, then publish:

`Windows\dist\codex-session-manager.exe`

## Files The App Creates

The app stores title overrides and CLI settings in your sessions directory:

- `<sessions_dir>\session mananger\titles\session_titles.json`
- `<sessions_dir>\session mananger\settings.json`

The app config file on Windows is stored at:

`%APPDATA%\.codex_session_manager\config.json`

## Troubleshooting

### Tkinter import fails

Reinstall Python on Windows and make sure Tcl/Tk support is included.

### Resume does not work

In PowerShell, check:

```powershell
Get-Command codex
```

If PowerShell cannot find `codex`, fix your Codex CLI installation or Windows `PATH`.

### PowerShell blocks local scripts

Run PowerShell as your user and allow local script execution for the current user if needed:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Git Bash does not appear in the shell dropdown

Install Git for Windows or make sure Git Bash is installed in a standard location that the app can detect.
