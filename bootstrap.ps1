$ErrorActionPreference = "Stop"
Set-Location (Split-Path $MyInvocation.MyCommand.Path)

$venv = Join-Path $PSScriptRoot "lib\venv"
$py = Join-Path $PSScriptRoot "lib\venv\Scripts\python.exe"

if (-not (Test-Path $py)) {
    Write-Host "[NetProof] creating virtualenv..."
    python -m venv $venv
}

Write-Host "[NetProof] installing dependencies..."
& $py -m pip install --upgrade pip
& $py -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")

Write-Host ""
Write-Host "[NetProof] ready. Start it with .\run.ps1" -ForegroundColor Green