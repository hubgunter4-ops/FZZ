$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { Join-Path $Root ".venv\Scripts\python.exe" }
if (-not (Test-Path $Python)) { $Python = "py" }

& $Python -m pip install --upgrade pyinstaller
Set-Location $Root
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
& $Python -m PyInstaller --clean --noconfirm fzz.spec
Write-Host "Build complete: $Root\dist\fzz.exe"
