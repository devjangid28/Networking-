$ErrorActionPreference = "Stop"
Set-Location (Split-Path $MyInvocation.MyCommand.Path)

$py = Join-Path $PSScriptRoot "lib\venv\Scripts\python.exe"
$backend = Join-Path $PSScriptRoot "backend"

if (-not (Test-Path $py)) {
    Write-Host "[NetProof] venv not found - run bootstrap.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  NetProof - neutral network-change validation" -ForegroundColor Cyan
Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Open http://127.0.0.1:8000  - Ctrl+C to stop" -ForegroundColor Gray
Write-Host ""

try {
    Push-Location $backend
    & $py -m uvicorn main:app --host 127.0.0.1 --port 8000
}
finally {
    Pop-Location
}