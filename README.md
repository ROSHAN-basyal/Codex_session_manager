# Codex Session Manager

Codex Session Manager is a desktop GUI for browsing and managing local Codex sessions.

It reads your local session logs, shows them in a searchable list, lets you inspect session details, rename sessions, open the original working directory or log file, and resume a session directly from the app.

## What It Does

- lists local Codex sessions from your `.codex/sessions` folder
- lets you search by title, path, cwd, or session ID
- shows session metadata in a side panel
- allows custom titles for easier organization
- resumes a session with `codex resume <session_id>`
- opens the session cwd, log file, or a terminal in that cwd

## Download A Prebuilt Version

If you only want to use the app and do not want to build it yourself, check the platform folders:

### Linux

Prebuilt Linux artifacts are kept in:

- `Linux/dist/codex-session-manager`
- `Linux/dist/Codex-Session-Manager.AppImage`

For most Linux users, the AppImage is the easiest option.

### Windows

The repository may contain a prebuilt Windows executable in:

- `Windows/dist/session_manager_V3.exe`

However, Windows users are strongly encouraged to build the app themselves.

Reason:

- the current Windows prebuilt build still works
- but it is behind the current source version
- and the UI quality is not as good as the current codebase

If you want the most up-to-date Windows version, build a fresh one from source.

## Build It Yourself

If you want to build or run the project from source, use the detailed guides:

- [guide_for_linux.md](guide_for_linux.md)
- [guide_for_windows.md](guide_for_windows.md)

Those guides cover setup, virtual environments, running from source, building distributables, and troubleshooting in detail.

## Small Technical Notes

- shared application code lives in the repository root
- Linux-specific assets, scripts, and prebuilt files live in `Linux/`
- Windows-specific assets, scripts, and prebuilt files live in `Windows/`
- the main app entrypoint is `codex_session_manager.py`
- build-time Python dependencies are listed in `requirements-build.txt`

## Where The App Stores Its Own Data

The app stores custom title overrides and CLI preferences inside your Codex sessions folder:

- `<sessions_dir>/session mananger/titles/session_titles.json`
- `<sessions_dir>/session mananger/settings.json`

App config is stored per platform:

- Linux: `${XDG_CONFIG_HOME:-~/.config}/.codex_session_manager/config.json`
- Windows: `%APPDATA%\.codex_session_manager\config.json`

## Platform Notes

### Linux

The Linux build path is current and includes prebuilt distributables in `Linux/dist/`.

### Windows

The Windows build scripts are current, but the checked-in prebuilt executable may lag behind the latest source changes. Build locally on Windows if you want the newest version and the updated UI.
