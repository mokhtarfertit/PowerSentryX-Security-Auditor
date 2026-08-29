[CmdletBinding()]

param (
    [string]$ConfigPath = (
        Join-Path -Path $PSScriptRoot -ChildPath 'config/settings.psd1'
    )
)

Set-StrictMode -Version Latest

$modulePaths = @(
    'utils/Helpers.psm1'
    'utils/PrivilegeCheck.psm1'
    'utils/Logger.psm1'
)

foreach ($modulePath in $modulePaths) {
    $fullModulePath = Join-Path -Path $PSScriptRoot -ChildPath $modulePath

    Import-Module -Name $fullModulePath -Force -ErrorAction Stop
}

$settings = Get-PowerSentryXSettings `
    -Path $ConfigPath `
    -ErrorAction stop 
$isAdministrator = Test-PowerSentryXAdministrator

$runId = [guid]::NewGuid().ToString()
$startedAtUtc = (Get-Date).ToUniversalTime()

Write-PowerSentryXLog `
    -Message "Audit started . Run ID: $runId" `
    -Level 'INFO' `
    -ErrorAction Stop

if ($isAdministrator) {
    Write-PowerSentryXLog `
        -Message 'PowerSentry is running with adminstrator privileges.' `
        -Leve 'INFO' `
        -ErrorAction stop
}
else {
    Write-PowerSentryXLog `
        -Message 'PowerSentryX is not running with administrator privileges. some checks may be unavailable.' `
        -Level 'WARNING' `
        -ErrorAction Stop
}

$runContext = [pscustomobject]@{
    RunId = $runId
    starteAtUtc = $startedAtUtc
    isAdministrator = $isAdministrator
    EnableCollectors = $settings.EnableCollectors
}

return $runContext