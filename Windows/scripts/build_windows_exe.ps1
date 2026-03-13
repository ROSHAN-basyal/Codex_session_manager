param()

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$VenvDir = Join-Path $RootDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPyInstaller = Join-Path $VenvDir "Scripts\pyinstaller.exe"
$OutputDir = Join-Path $RootDir "Windows\dist"
$AppName = "codex-session-manager"
$SpecFile = Join-Path $RootDir "$AppName.spec"
$BuildDir = Join-Path $RootDir "build\$AppName"

if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment not found. Run .\Windows\scripts\setup_windows_venv.ps1 first."
}

if (-not (Test-Path $VenvPyInstaller)) {
    Write-Host "Installing build dependency into .venv"
    & (Join-Path $VenvDir "Scripts\pip.exe") install -r (Join-Path $RootDir "requirements-build.txt")
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $OutputDir "$AppName.exe") -ErrorAction SilentlyContinue
Remove-Item -Force $SpecFile -ErrorAction SilentlyContinue

& $VenvPyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name $AppName `
    --distpath $OutputDir `
    (Join-Path $RootDir "codex_session_manager.py")

Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
Remove-Item -Force $SpecFile -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $RootDir "build") -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Build complete:"
Write-Host "  $OutputDir\$AppName.exe"
