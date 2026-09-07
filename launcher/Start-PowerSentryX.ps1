[CmdletBinding()]
param (
    [ValidateSet('Audit', 'Monitor')]
    [string]$Mode = 'Audit',

    [string]$ConfigPath,

    [string]$MonitorStatePath,

    [int]$MonitorIntervalSeconds = 60,

    [ValidateRange(1, 1000)]
    [int]$Iterations = 1
)

Set-StrictMode -Version Latest

$projectRoot = Split-Path -Path $PSScriptRoot -Parent
$controllerPath = Join-Path -Path $projectRoot -ChildPath 'PowerSentryX.ps1'
$bannerPath = Join-Path -Path $PSScriptRoot -ChildPath 'Banner.psm1'

if (-not (Test-Path -LiteralPath $controllerPath)) {
    throw "PowerSentryX controller was not found: $controllerPath"
}

Import-Module -Name $bannerPath -Force -ErrorAction Stop

Show-PowerSentryXBanner -Version '0.1.0' -Mode $Mode

$controllerParameters = @{
    Mode = $Mode
    MonitorIntervalSeconds = $MonitorIntervalSeconds
    Iterations = $Iterations
}

if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $controllerParameters.ConfigPath = $ConfigPath
}

if (-not [string]::IsNullOrWhiteSpace($MonitorStatePath)) {
    $controllerParameters.MonitorStatePath = $MonitorStatePath
}

$results = @(
    & $controllerPath @controllerParameters
)

foreach ($result in $results) {
    Show-PowerSentryXRunSummary -Context $result
}

return $results
