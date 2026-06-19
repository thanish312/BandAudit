[CmdletBinding()]
param(
    [switch]$ShowSteps
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Frontend = Join-Path $Root "frontend"
$EnvFile = Join-Path $Root ".env"
$ApiBase = "http://127.0.0.1:8000"
$AppBase = "http://127.0.0.1:5173"

$Blockers = New-Object System.Collections.Generic.List[string]
$Warnings = New-Object System.Collections.Generic.List[string]

function Write-Status {
    param(
        [string]$Label,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    Write-Host ("{0,-10} {1}" -f $Label, $Message) -ForegroundColor $Color
}

function Add-Blocker {
    param([string]$Message)
    $script:Blockers.Add($Message) | Out-Null
    Write-Status "[BLOCKER]" $Message Red
}

function Add-Warning {
    param([string]$Message)
    $script:Warnings.Add($Message) | Out-Null
    Write-Status "[WARN]" $Message Yellow
}

function Add-Pass {
    param([string]$Message)
    Write-Status "[OK]" $Message Green
}

function Get-Json {
    param([string]$Url)
    return Invoke-RestMethod -Uri $Url -TimeoutSec 12
}

function Test-Http {
    param([string]$Url)
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 8
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
    }
    catch {
        return $false
    }
}

function Read-DotEnv {
    param([string]$Path)

    $values = @{}
    if (!(Test-Path -LiteralPath $Path)) {
        return $values
    }

    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (!$trimmed -or $trimmed.StartsWith("#") -or !$trimmed.Contains("=")) {
            continue
        }
        $key, $value = $trimmed.Split("=", 2)
        $values[$key.Trim()] = $value.Trim().Trim('"')
    }
    return $values
}

function Get-PeerCount {
    param([string]$Json)

    if (!$Json -or $Json -eq "{}") {
        return 0
    }
    try {
        $parsed = $Json | ConvertFrom-Json
        return @($parsed.PSObject.Properties).Count
    }
    catch {
        Add-Warning "BAND_LANE_PEERS_JSON is not valid JSON. Peer recruitment will be skipped if enabled."
        return 0
    }
}

Write-Host ""
Write-Host "BandAudit demo readiness check" -ForegroundColor Cyan
Write-Host "This script is non-mutating: it does not create rooms, lock packets, import files, or advance reviews." -ForegroundColor DarkGray
Write-Host ""

try {
    & (Join-Path $PSScriptRoot "start.ps1") | Out-Host
}
catch {
    Add-Blocker "Could not start/check local servers: $($_.Exception.Message)"
}

if (!(Test-Http -Url $AppBase)) {
    Add-Blocker "Frontend is not reachable at $AppBase"
}
else {
    Add-Pass "Frontend reachable at $AppBase"
}

$health = $null
$source = $null
$providers = $null
$audit = $null

try {
    $health = Get-Json "$ApiBase/health"
    if ($health.status -eq "ok") {
        Add-Pass "Backend health endpoint is OK."
    }
    else {
        Add-Blocker "Backend health endpoint did not return ok."
    }
}
catch {
    Add-Blocker "Backend health endpoint failed: $($_.Exception.Message)"
}

try {
    $sourceResponse = Get-Json "$ApiBase/api/audit/source"
    $source = $sourceResponse.diagnostics
    if ($sourceResponse.status -eq "ok" -and $source.effective_mode -eq "band") {
        Add-Pass "Band source is live for room $($source.room_id)."
    }
    else {
        Add-Blocker "Band source is not ready. Status=$($sourceResponse.status), mode=$($source.effective_mode), error=$($sourceResponse.read_error)"
    }
}
catch {
    Add-Blocker "Band diagnostics failed: $($_.Exception.Message)"
}

try {
    $providers = Get-Json "$ApiBase/api/audit/providers"
    $providerRows = @($providers.providers)
    $routeRows = @($providers.routes)
    $notReady = @($providerRows | Where-Object { $_.status -ne "ready" })
    $missingRouteModels = @($routeRows | Where-Object { !$_.model })

    if ($providers.effective_mode -eq "live" -and $notReady.Count -eq 0) {
        Add-Pass "AI/ML API and Featherless provider diagnostics are ready."
    }
    else {
        Add-Blocker "Provider diagnostics are not ready. Mode=$($providers.effective_mode); not-ready providers=$($notReady.Count)."
    }

    if ($routeRows.Count -gt 0 -and $missingRouteModels.Count -eq 0) {
        Add-Pass "Route-level models are configured for $($routeRows.Count) release-board lanes."
    }
    else {
        Add-Blocker "One or more release-board routes are missing model assignments."
    }

    Write-Host ""
    Write-Host "Release-board route table" -ForegroundColor Cyan
    foreach ($route in $routeRows) {
        Write-Host ("- {0}: {1} / {2}" -f $route.agent, $route.provider, $route.model)
    }
}
catch {
    Add-Blocker "Provider diagnostics failed: $($_.Exception.Message)"
}

$envValues = Read-DotEnv -Path $EnvFile
$ocrModel = $envValues["AIML_OCR_MODEL"]
if ($ocrModel) {
    Add-Pass "PDF import OCR model configured: $ocrModel"
}
else {
    Add-Blocker "AIML_OCR_MODEL is missing from .env. PDF packet import cannot prove the OCR path."
}

$recruitEnabled = ($envValues["BAND_RECRUIT_LANE_PEERS"] -eq "true")
$peerCount = Get-PeerCount -Json $envValues["BAND_LANE_PEERS_JSON"]
if ($recruitEnabled) {
    if ($peerCount -gt 0) {
        Add-Pass "Optional Band lane peer recruitment is enabled with $peerCount configured peer mapping(s)."
    }
    else {
        Add-Warning "Band lane peer recruitment is enabled but no peer mappings are configured."
    }
}
else {
    Add-Warning "Band lane peer recruitment is disabled. Demo will use one Band external agent with declared structured lanes."
}

try {
    $audit = Get-Json "$ApiBase/api/audit"
    $events = @($audit.events)
    $initWithManifest = @($events | Where-Object { $_.event_type -eq "audit_init" -and $_.metadata.band_room_manifest } | Select-Object -First 1)

    if ($events.Count -eq 0) {
        Add-Pass "Current Band room has no BandAudit events. It is clean for recording."
    }
    elseif ($initWithManifest.Count -gt 0) {
        Add-Warning "Current Band room already contains $($events.Count) event(s) with a locked packet manifest. Use a fresh room for a clean recording."
    }
    else {
        Add-Warning "Current Band room contains $($events.Count) event(s) but no locked packet manifest. Old or partial room trace; create a fresh Band room before recording."
    }
}
catch {
    Add-Blocker "Audit state inspection failed: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Recording checklist" -ForegroundColor Cyan
if ($ShowSteps) {
    Write-Host "1. Open $AppBase/setup and create a fresh Band room."
    Write-Host "2. Choose Start sample audit, create a manual packet, or import your own release packet PDF."
    Write-Host "3. Review packet fields, then Lock packet and start review."
    Write-Host "4. Show the running release-board progress card."
    Write-Host "5. Show Review roster/provenance, Timeline room trace, and Report integrity/export."
}
else {
    Write-Host "Run .\scripts\demo-ready.ps1 -ShowSteps to print the exact recording steps."
}

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
Write-Host ("Blockers: {0}" -f $Blockers.Count)
Write-Host ("Warnings: {0}" -f $Warnings.Count)

if ($Blockers.Count -gt 0) {
    exit 1
}

exit 0
