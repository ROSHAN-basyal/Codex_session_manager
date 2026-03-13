param(
    [string]$SessionsDir = "",
    [string]$TitlesFile = "",
    [string]$SettingsFile = ""
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment not found. Run .\Windows\scripts\setup_windows_venv.ps1 first."
}

$ArgsList = @("$RootDir\codex_session_manager.py")
if ($SessionsDir) { $ArgsList += @("--sessions-dir", $SessionsDir) }
if ($TitlesFile) { $ArgsList += @("--titles-file", $TitlesFile) }
if ($SettingsFile) { $ArgsList += @("--settings-file", $SettingsFile) }

& $VenvPython @ArgsList
