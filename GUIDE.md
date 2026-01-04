# User Guide

## First Run
Open the app and pick your `.codex` folder or any subfolder inside it. The app will locate `...\.codex\sessions` automatically and save that location for next time.

## Search
Type in the search bar and click Search (or press Enter). The search is case-insensitive and matches partial words like `Hell` → `hello`.

## Sorting
Click the Title, Created, or Updated column headers to sort. Click again to toggle ascending/descending.

## Titles
Select a session and edit the Title field on the right. Click Save Title or press Enter. Use Reset Title to restore the auto-generated title.

Untitled sessions are labeled `Untitled_session_1`, `Untitled_session_2`, and so on, based on creation time.

## Resume
Pick a CLI from the dropdown and click Resume. The app opens a new terminal, changes to the session `cwd`, and runs `codex resume <session_id>`.

## Files Created
The app stores custom titles and CLI settings inside your Codex sessions folder:

`<sessions_dir>\session mananger\titles\session_titles.json`

`<sessions_dir>\session mananger\settings.json`
