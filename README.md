# Codex Session Browser

This GUI reads Codex session logs from your local machine and helps you search, inspect, and resume sessions. It only saves your custom session titles.

## Run

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
- App config is stored at `C:\Users\Asus\.codex_session_manager\config.json`
