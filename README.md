# Codex Session Browser

This GUI reads Codex session logs from your local machine and helps you search, inspect, and resume sessions. It only saves your custom session titles.

## Run

Use the built executable (recommended on Windows):

```
dist/session_manager.exe
```

Or run from source:

```powershell
python codex_session_manager.py
```

On first run, it opens a folder picker so you can choose your `.codex` folder (or any subfolder inside it).
The selection is saved for next time.

Optional override for the sessions directory:

```powershell
python codex_session_manager.py --sessions-dir "C:\Users\Asus\.codex\sessions"
```

## What you can do

- Search by title, cwd, session id, or file path
- Double-click a row (or click Resume) to launch `codex resume <session_id>`
- Choose a CLI from the dropdown (default is saved and marked as `(default)` and used for Resume)
- Open the original working directory
- Open the session log file
- Edit titles (stored in `C:\Users\Asus\.codex\sessions\session mananger\titles\session_titles.json` by default)
- Sort by Title, Created, or Updated via the column headers
- App config is stored at `C:\Users\Asus\.codex_session_manager\config.json`

## Setup notes

- On first run, the app opens a folder picker (like an installer). Select `.codex` or any subfolder inside it.
- The app resolves the correct `...\.codex\sessions` directory and creates `session mananger/titles/session_titles.json`.
- The app also creates `session mananger/settings.json` in the same place.
- The chosen location is saved in `C:\Users\Asus\.codex_session_manager\config.json`.

## GUI overview

- Top bar: search field with inline clear, plus Search and Refresh buttons.
- Center: sortable session table (Title, Created, Updated, CWD, Session ID).
- Right panel: title editor, session details, CLI dropdown, and action buttons.

See `GUIDE.md` for more details.
