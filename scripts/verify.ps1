[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$BackendPython = Join-Path $Backend ".venv\Scripts\python.exe"

if (!(Test-Path -LiteralPath $BackendPython)) {
    throw "Backend virtual environment is missing. Run .\scripts\start.ps1 -Install first."
}

Write-Host "Checking backend"
Push-Location $Backend
try {
    & $BackendPython -m compileall app
    & $BackendPython -m pip check
}
finally {
    Pop-Location
}

Write-Host "Checking frontend"
Push-Location $Frontend
try {
    npm run build
    npm audit --audit-level=high
}
finally {
    Pop-Location
}

Write-Host "Checking running API"
$health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 10
$source = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/audit/source" -TimeoutSec 10
$providers = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/audit/providers" -TimeoutSec 10
$audit = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/audit" -TimeoutSec 20

if ($health.status -ne "ok") {
    throw "Backend health check failed."
}
if ($source.status -ne "ok") {
    throw "Source diagnostics failed."
}
if ($source.diagnostics.source -ne "band" -or $source.diagnostics.effective_mode -ne "band") {
    throw "Band diagnostics expected effective mode band."
}
if ($providers.effective_mode -ne "live") {
    throw "Agent execution expected live providers."
}

Write-Host ""
Write-Host "Verification passed"
Write-Host "Event source: $($health.event_source) ($($health.effective_mode))"
Write-Host "Agent execution: $($providers.effective_mode)"
Write-Host "Current room event count: $($audit.events.Count)"
Write-Host "Provider statuses:"
$providers.providers | ForEach-Object {
    Write-Host "  $($_.provider): $($_.status)"
}
