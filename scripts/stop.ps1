[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Ports = 8000, 5173
$Stopped = @()
$StoppedIds = New-Object System.Collections.Generic.HashSet[int]

foreach ($port in $Ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($connection in $connections) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($connection.OwningProcess)" -ErrorAction SilentlyContinue
        if ($null -eq $process) {
            continue
        }

        $commandLine = [string]$process.CommandLine
        if ($commandLine.Contains($Root) -and !$StoppedIds.Contains([int]$connection.OwningProcess)) {
            Stop-Process -Id $connection.OwningProcess -Force
            $StoppedIds.Add([int]$connection.OwningProcess) | Out-Null
            $Stopped += "$($connection.OwningProcess) on port $port"
        }
    }
}

$repoProcesses = Get-CimInstance Win32_Process | Where-Object {
    $commandLine = [string]$_.CommandLine
    $commandLine.Contains($Root) -and (
        $commandLine -match "uvicorn" -or
        $commandLine -match "app\.main:app" -or
        $commandLine -match "vite" -or
        $commandLine -match "npm(\.cmd)? run dev"
    )
}

foreach ($process in $repoProcesses) {
    if ($StoppedIds.Contains([int]$process.ProcessId)) {
        continue
    }
    Stop-Process -Id $process.ProcessId -Force
    $StoppedIds.Add([int]$process.ProcessId) | Out-Null
    $Stopped += "$($process.ProcessId) background server"
}

if ($Stopped.Count -eq 0) {
    Write-Host "No BandAudit server processes were stopped."
}
else {
    Write-Host "Stopped BandAudit processes:"
    $Stopped | ForEach-Object { Write-Host "  $_" }
}
