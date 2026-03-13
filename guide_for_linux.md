# Linux Guide

## Purpose

This guide explains, step by step, how to set up, run, use, and build the Codex Session Browser on Linux.

The repository is organized like this:

- shared application code is in the repository root
- Linux-only scripts and distributables are in `Linux/`
- Windows-only scripts and distributables are in `Windows/`

The shared GUI entrypoint is:

`codex_session_manager.py`

## What The App Does

The app reads local Codex session files from your `.codex/sessions` directory, shows them in a GUI, lets you search and rename them, and allows you to resume a session by launching:

`codex resume <session_id>`

## Linux Requirements

You need all of the following before the GUI can work correctly:

- Python 3 installed and available on `PATH`
- Tk support available in the Linux Python runtime
- a graphical desktop session
- `xdg-open` for opening files and folders
- a supported terminal emulator if you want Resume and Open CWD in Terminal to work

Recommended terminal emulators:

- `gnome-terminal`
- `konsole`
- `kitty`
- `xfce4-terminal`
- `tilix`
- `alacritty`
- `xterm`

For Arch / EndeavourOS, install the required system packages with:

```bash
sudo pacman -S python tk xdg-utils
```

If you do not already have a supported terminal emulator, install one, for example:

```bash
sudo pacman -S kitty
```

## Step 1: Open The Project Folder

Open a terminal and change into the project directory:

```bash
cd /home/rsnb/Documents/My_projects/Codex_session_manager
```

If your clone is somewhere else, use that path instead.

## Step 2: Create The Python Virtual Environment

Run:

```bash
python -m venv .venv
```

This creates a local virtual environment in:

`.venv/`

## Step 3: Activate The Virtual Environment

From the repository root, run:

```bash
source .venv/bin/activate
```

When activation succeeds, your shell prompt usually shows:

`(.venv)`

## Step 4: Run The Linux Setup Script

From the repository root, run:

```bash
./Linux/scripts/setup_linux_venv.sh
```

This script does the following:

- checks that Python exists
- creates `.venv` if it does not already exist
- installs `customtkinter` into the virtual environment
- checks that Tk can be imported
- checks that `xdg-open` exists
- checks for a supported terminal emulator
- warns you if `codex` is not on `PATH`

If the script stops with a Tk error, install the required Linux packages first and rerun it.

## Step 5: Run The App From Source

From the repository root, run:

```bash
./Linux/scripts/run_linux_gui.sh
```

That script:

- checks that `.venv` exists
- checks that you are in a graphical desktop session
- runs the shared application using `.venv/bin/python`

You can also run the shared file directly:

```bash
python codex_session_manager.py
```

If you want to force a specific sessions directory, use:

```bash
python codex_session_manager.py --sessions-dir "$HOME/.codex/sessions"
```

## Step 6: First Launch Behavior

When the app starts, it chooses the sessions directory in this order:

1. the value passed through `--sessions-dir`
2. the previously saved app config
3. the default `~/.codex/sessions`, if it exists
4. a folder picker

If `~/.codex/sessions` exists, the app uses it automatically.

If it does not exist, the app opens a folder picker. You can select:

- the `.codex` folder itself
- the `sessions` folder
- any subfolder inside `.codex`

The app resolves the real sessions directory from your selection.

## Step 7: Basic UI Usage

### Search

Use the search field at the top to filter sessions by:

- title
- working directory
- session ID
- log file path

You can:

- press `Enter` in the search field
- click `Search`
- click `Clear` to remove the filter

### Sessions List

The left panel shows the sessions list.

Each session row includes:

- a small resume glyph before the title
- created timestamp
- updated timestamp
- cwd
- short session ID

You can:

- click a row to load its details
- double-click a row to resume it
- click the small resume glyph area at the start of the title cell to resume that session directly
- use the horizontal or vertical scrollbars if the list is larger than the visible area

### Session Details Panel

The right panel shows:

- editable title
- session ID
- created timestamp
- updated timestamp
- cwd
- log file path
- CLI shell selection
- action buttons

The entire details panel is scrollable. If the window becomes too small and the details panel moves below the sessions list, you can still scroll that panel and view all fields.

### Sorting

You can sort by:

- Title
- Created
- Updated

Click a sortable column header once to sort.

Click it again to reverse the sort direction.

## Step 8: Resume A Session

To resume a session:

1. select a session row
2. choose a shell in the CLI dropdown if one is not already selected
3. click `Resume Session`

The app opens a terminal, changes into the session cwd if one exists, and runs:

`codex resume <session_id>`

Resume will only work if the `codex` command is available on your Linux `PATH`.

## Step 9: Open Files And Folders

The details panel gives you these actions:

- `Copy ID`
- `Open CWD`
- `CWD in Terminal`
- `Open Log`

On Linux:

- file and folder opening uses `xdg-open`
- terminal opening uses one of the supported terminal emulators

## Step 10: Build A Linux Binary

To build a single-file Linux executable, first activate the virtual environment:

```bash
source .venv/bin/activate
```

Then install the build dependency:

```bash
pip install -r requirements-build.txt
```

Then build:

```bash
./Linux/scripts/build_linux_binary.sh
```

The output file is:

`Linux/dist/codex-session-manager`

This file is intended to stay inside `Linux/dist/` so it can be committed to GitHub as a prebuilt Linux binary.

## Step 11: Build A Linux AppImage

To build the AppImage, run:

```bash
./Linux/scripts/build_linux_appimage.sh
```

The output file is:

`Linux/dist/Codex-Session-Manager.AppImage`

This file is also intended to stay inside `Linux/dist/` so it can be uploaded to GitHub as a prebuilt Linux AppImage.

To run that AppImage on another Linux machine:

```bash
chmod +x Linux/dist/Codex-Session-Manager.AppImage
./Linux/dist/Codex-Session-Manager.AppImage
```

## Files The App Creates

The app stores title overrides and CLI settings inside the sessions directory:

- `<sessions_dir>/session mananger/titles/session_titles.json`
- `<sessions_dir>/session mananger/settings.json`

The app config file on Linux is stored at:

`${XDG_CONFIG_HOME:-~/.config}/.codex_session_manager/config.json`

## Troubleshooting

### Tkinter fails to import

Install Tk support for Python:

```bash
sudo pacman -S tk
```

### `xdg-open` is missing

Install:

```bash
sudo pacman -S xdg-utils
```

### Resume does not work

Make sure `codex` is on `PATH`:

```bash
which codex
```

If nothing is returned, fix your Codex CLI installation or shell `PATH`.

### No terminal opens

Install a supported terminal emulator, for example:

```bash
sudo pacman -S kitty
```
