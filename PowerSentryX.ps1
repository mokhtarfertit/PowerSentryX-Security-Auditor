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

    'modules/collectors/SystemInfo.psm1'
    'modules/collectors/Firewall.psm1'
    'modules/collectors/UserAudit.psm1'
    'modules/collectors/DefenderAudit.psm1'
    'modules/collectors/NetworkAudit.psm1'
    'modules/collectors/ProcessAudit.psm1'
    'modules/collectors/ServiceAudit.psm1'
    'modules/collectors/ScheduledTaskAudit.psm1'
    'modules/collectors/SecurityPolicyAudit.psm1'

    'modules/analysis/SecurityAnalyzer.psm1'
    'modules/reporting/ReportGenerator.psm1'
)

foreach ($modulePath in $modulePaths) {
    $fullModulePath = Join-Path -Path $PSScriptRoot -ChildPath $modulePath
    Import-Module -Name $fullModulePath -Force -ErrorAction Stop
}

$settings = Get-PowerSentryXSettings -Path $ConfigPath -ErrorAction Stop

if (-not $settings.ContainsKey('EnabledCollectors')) {
    throw "Configuration is missing the 'EnabledCollectors' setting."
}

$isAdministrator = Test-PowerSentryXAdministrator

$runId = [guid]::NewGuid().ToString()
$startedAtUtc = (Get-Date).ToUniversalTime()

Write-PowerSentryXLog -Message "Audit started. Run ID: $runId" -Level 'INFO' -ErrorAction Stop

if ($isAdministrator) {
    Write-PowerSentryXLog -Message 'PowerSentryX is running with administrator privileges.' -Level 'INFO' -ErrorAction Stop
}
else {
    Write-PowerSentryXLog -Message 'PowerSentryX is not running with administrator privileges. Some checks may be unavailable.' -Level 'WARNING' -ErrorAction Stop
}

$collectorResults = @()

foreach ($collectorName in $settings.EnabledCollectors) {
    switch ($collectorName) {
        'SystemInfo' {
            $collectorResult = Invoke-PowerSentryXSystemInfoCollector
            $collectorResults += $collectorResult
        }

        'Firewall' {
            $collectorResult = Invoke-PowerSentryXFirewallCollector
            $collectorResults += $collectorResult
        }

        'UserAudit' {
            $collectorResult = Invoke-PowerSentryXUserAuditCollector
            $collectorResults += $collectorResult
        }

        'DefenderAudit' {
            $collectorResult = Invoke-PowerSentryXDefenderAuditCollector
            $collectorResults += $collectorResult
        }

        'NetworkAudit' {
            $collectorResult = Invoke-PowerSentryXNetworkAuditCollector
            $collectorResults += $collectorResult
        }

        'ProcessAudit' {
            $collectorResult = Invoke-PowerSentryXProcessAuditCollector
            $collectorResults += $collectorResult
        }

        'ServiceAudit' {
            $collectorResult = Invoke-PowerSentryXServiceAuditCollector
            $collectorResults += $collectorResult
        }

        'ScheduledTaskAudit' {
            $collectorResult = Invoke-PowerSentryXScheduledTaskAuditCollector
            $collectorResults += $collectorResult
        }

        'SecurityPolicyAudit' {
            $collectorResult = Invoke-PowerSentryXSecurityPolicyAuditCollector
            $collectorResults += $collectorResult
        }
        

        default {
            Write-PowerSentryXLog -Message "Unknown collector configured: $collectorName" -Level 'WARNING' -ErrorAction Stop

            $collectorResults += [pscustomobject]@{
                CollectorId    = $collectorName
                CollectedAtUtc = (Get-Date).ToUniversalTime()
                Status         = 'Unavailable'
                Data           = @()
                Errors         = @(
                    "No implementation exists for collector '$collectorName'."
                )
            }
        }
    }
}

$runContext = [pscustomobject]@{
    RunId              = $runId
    StartedAtUtc       = $startedAtUtc
    IsAdministrator    = $isAdministrator
    EnabledCollectors  = $settings.EnabledCollectors
    CollectorResults   = $collectorResults
}

$reportDirectory = Join-Path -Path $PSScriptRoot -ChildPath $settings.Reporting.OutputDirectory

$reportPath = Write-PowerSentryXJsonReport -AuditContext $runContext -OutputDirectory $reportDirectory -ErrorAction Stop

Write-PowerSentryXLog -Message "JSON report created: $reportPath" -Level 'INFO' -ErrorAction Stop

$runContext = [pscustomobject]@{
    RunId              = $runId
    StartedAtUtc       = $startedAtUtc
    IsAdministrator    = $isAdministrator
    EnabledCollectors  = $settings.EnabledCollectors
    CollectorResults   = $collectorResults
    ReportPath         = $reportPath
}

return $runContext