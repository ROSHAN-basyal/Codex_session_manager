# User Guide

## First Run
If `~/.codex/sessions` already exists, the app uses it automatically.

If not, the app opens a folder picker. You can choose your `.codex` folder or any subfolder inside it. The app resolves the correct sessions directory and saves it for the next run.

On Linux, the recommended start flow is:

```bash
./scripts/setup_linux_venv.sh
./scripts/run_linux_gui.sh
```

## Search
Type in the search bar and click Search (or press Enter). The search is case-insensitive and matches partial words like `Hell` → `hello`.

## Sorting
Click the Title, Created, or Updated column headers to sort. Click again to toggle ascending/descending.

## Titles
Select a session and edit the Title field on the right. Click Save Title or press Enter. Use Reset Title to restore the auto-generated title.

Untitled sessions are labeled `Untitled_session_1`, `Untitled_session_2`, and so on, based on creation time.

## Resume
Pick a CLI from the dropdown and click Resume. The app opens a new terminal, changes to the session `cwd`, and runs `codex resume <session_id>`.

On Linux, Resume and Open CWD in Terminal require a supported terminal emulator such as `gnome-terminal`, `konsole`, `kitty`, `xfce4-terminal`, `tilix`, `alacritty`, or `xterm`.

## Files Created
The app stores custom titles and CLI settings inside your Codex sessions folder:

`<sessions_dir>/session mananger/titles/session_titles.json`

`<sessions_dir>/session mananger/settings.json`

The app config file is stored here:

- Linux: `${XDG_CONFIG_HOME:-~/.config}/.codex_session_manager/config.json`
- Windows: `%APPDATA%\.codex_session_manager\config.json`
