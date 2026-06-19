[CmdletBinding()]
param(
    [switch]$Install
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$BackendPython = Join-Path $Backend ".venv\Scripts\python.exe"
$BackendRequirements = Join-Path $Backend "requirements.txt"
$FrontendModules = Join-Path $Frontend "node_modules"

function Test-HttpOk {
    param([string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
    }
    catch {
        return $false
    }
}

function Test-PortListening {
    param([int]$Port)

    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Wait-ForHttp {
    param(
        [string]$Url,
        [int]$Seconds = 25
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-HttpOk -Url $Url) {
            return
        }
        Start-Sleep -Milliseconds 500
    }

    throw "Timed out waiting for $Url"
}

if (!(Test-Path -LiteralPath $BackendPython)) {
    Write-Host "Creating backend virtual environment"
    Push-Location $Backend
    try {
        python -m venv .venv
    }
    finally {
        Pop-Location
    }
    $Install = $true
}

if ($Install) {
    Write-Host "Installing backend dependencies"
    & $BackendPython -m pip install -r $BackendRequirements
}

if (!(Test-Path -LiteralPath $FrontendModules) -or $Install) {
    Write-Host "Installing frontend dependencies"
    Push-Location $Frontend
    try {
        npm install
    }
    finally {
        Pop-Location
    }
}

if (Test-HttpOk -Url "http://127.0.0.1:8000/health") {
    Write-Host "Backend already running on http://127.0.0.1:8000"
}
elseif (Test-PortListening -Port 8000) {
    throw "Port 8000 is already in use. Run .\scripts\stop.ps1 if it belongs to BandAudit."
}
else {
    Write-Host "Starting backend on http://127.0.0.1:8000"
    Start-Process `
        -FilePath $BackendPython `
        -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" `
        -WorkingDirectory $Backend `
        -RedirectStandardOutput (Join-Path $Backend "server.out.log") `
        -RedirectStandardError (Join-Path $Backend "server.err.log") `
        -WindowStyle Hidden
    Wait-ForHttp -Url "http://127.0.0.1:8000/health"
}

if (Test-HttpOk -Url "http://127.0.0.1:5173") {
    Write-Host "Frontend already running on http://127.0.0.1:5173"
}
elseif (Test-PortListening -Port 5173) {
    throw "Port 5173 is already in use. Run .\scripts\stop.ps1 if it belongs to BandAudit."
}
else {
    Write-Host "Starting frontend on http://127.0.0.1:5173"
    Start-Process `
        -FilePath "npm.cmd" `
        -ArgumentList "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173" `
        -WorkingDirectory $Frontend `
        -RedirectStandardOutput (Join-Path $Frontend "server.out.log") `
        -RedirectStandardError (Join-Path $Frontend "server.err.log") `
        -WindowStyle Hidden
    Wait-ForHttp -Url "http://127.0.0.1:5173"
}

Write-Host ""
Write-Host "BandAudit is running"
Write-Host "Frontend: http://127.0.0.1:5173"
Write-Host "Backend:  http://127.0.0.1:8000"
Write-Host "Health:   http://127.0.0.1:8000/health"
