$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { "py" }
$Venv = if ($env:FZZ_VENV) { $env:FZZ_VENV } else { Join-Path $Root ".venv" }

& $Python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 2)"
if ($LASTEXITCODE -ne 0) {
    throw "FZZ requiere Python 3.11 o posterior."
}

& $Python -m venv $Venv
$VenvPython = Join-Path $Venv "Scripts\python.exe"
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r (Join-Path $Root "requirements.txt")
if ($env:FZZ_INSTALL_DEV -eq "1") {
    & $VenvPython -m pip install -r (Join-Path $Root "requirements-dev.txt")
}
& $VenvPython -m pip install --editable $Root
& $VenvPython -m fzztool --version
Write-Host "FZZ quedó instalado en: $Venv"
Write-Host "Activa el entorno con: $Venv\Scripts\Activate.ps1"
