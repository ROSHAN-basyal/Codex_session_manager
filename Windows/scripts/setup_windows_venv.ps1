param()

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$VenvDir = Join-Path $RootDir ".venv"

Write-Host "Project root: $RootDir"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is not installed or not on PATH."
}

if (-not (Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment at $VenvDir"
    python -m venv $VenvDir
} else {
    Write-Host "Virtual environment already exists at $VenvDir"
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"

& $VenvPip install --quiet customtkinter

try {
    & $VenvPython -c "import tkinter; import customtkinter; print('Tkinter and CustomTkinter: OK')"
} catch {
    throw "Python can not load Tkinter. Reinstall Python for Windows with Tcl/Tk support enabled."
}

Write-Host ""
Write-Host "Windows GUI environment looks ready."
Write-Host "Launch the app with:"
Write-Host "  .\Windows\scripts\run_windows_gui.ps1"
