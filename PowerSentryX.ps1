[CmdletBinding()]
param (
    [ValidateSet('Audit', 'Monitor')]
    [string]$Mode = 'Audit',
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath 'config/settings.psd1'),
    [string]$MonitorStatePath = (Join-Path -Path $PSScriptRoot -ChildPath 'data/snapshots/monitor-state.json'),
    [int]$MonitorIntervalSeconds = 60,
    [ValidateRange(1, 1000)]
    [int]$Iterations = 1
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
    'modules/monitoring/EventLogMonitor.psm1'
    'modules/monitoring/FirewallMonitor.psm1'
    'modules/monitoring/DefenderMonitor.psm1'
    'modules/monitoring/UserMonitor.psm1'
    'modules/monitoring/ServiceMonitor.psm1'
    'modules/monitoring/ProcessMonitor.psm1'
    'modules/analysis/EventClassifier.psm1'
    'modules/analysis/SecurityAnalyzer.psm1'
    'modules/reporting/ReportGenerator.psm1'
)

foreach ($modulePath in $modulePaths) {
    $fullModulePath = Join-Path -Path $PSScriptRoot -ChildPath $modulePath
    if (-not (Test-Path -LiteralPath $fullModulePath)) {
        throw "Required module was not found: $fullModulePath"
    }
    Import-Module -Name $fullModulePath -Force -ErrorAction Stop
}

$settings = Get-PowerSentryXSettings -Path $ConfigPath -ErrorAction Stop

if (-not $settings.ContainsKey('EnabledCollectors')) {
    throw "Configuration is missing the 'EnabledCollectors' setting."
}

function Get-PreviousMonitorState {
    param ([psobject]$State, [string]$MonitorId)
    if ($null -eq $State) { return @() }
    $property = $State.PSObject.Properties[$MonitorId]
    if ($null -eq $property) { return @() }
    return $property.Value
}

function Invoke-PowerSentryXAuditRun {
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
            'SystemInfo' { $collectorResults += Invoke-PowerSentryXSystemInfoCollector }
            'Firewall' { $collectorResults += Invoke-PowerSentryXFirewallCollector }
            'UserAudit' { $collectorResults += Invoke-PowerSentryXUserAuditCollector }
            'DefenderAudit' { $collectorResults += Invoke-PowerSentryXDefenderAuditCollector }
            'NetworkAudit' { $collectorResults += Invoke-PowerSentryXNetworkAuditCollector }
            'ProcessAudit' { $collectorResults += Invoke-PowerSentryXProcessAuditCollector }
            'ServiceAudit' { $collectorResults += Invoke-PowerSentryXServiceAuditCollector }
            'ScheduledTaskAudit' { $collectorResults += Invoke-PowerSentryXScheduledTaskAuditCollector }
            'SecurityPolicyAudit' { $collectorResults += Invoke-PowerSentryXSecurityPolicyAuditCollector }
            default {
                $collectorResults += [pscustomobject]@{
                    CollectorId = $collectorName
                    CollectedAtUtc = (Get-Date).ToUniversalTime()
                    Status = 'Unavailable'
                    Data = @()
                    Errors = @("No implementation exists for collector '$collectorName'.")
                }
            }
        }
    }

    $findings = @(Invoke-PowerSentryXSecurityAnalyzer -CollectorResults $collectorResults)
    $findingSummary = Get-PowerSentryXFindingSummary -Findings $findings

    return [pscustomobject]@{
        RunId = $runId
        Mode = 'Audit'
        StartedAtUtc = $startedAtUtc
        IsAdministrator = $isAdministrator
        EnabledCollectors = $settings.EnabledCollectors
        CollectorResults = $collectorResults
        Findings = $findings
        FindingSummary = $findingSummary
    }
}

function Invoke-PowerSentryXMonitorRun {
    param ([psobject]$PreviousState)

    $runId = [guid]::NewGuid().ToString()
    $checkedAtUtc = (Get-Date).ToUniversalTime()
    $monitorResults = @()

    $monitorResults += Invoke-PowerSentryXFirewallMonitor -PreviousState @(Get-PreviousMonitorState $PreviousState 'FirewallMonitor')
    $monitorResults += Invoke-PowerSentryXDefenderMonitor -PreviousState (Get-PreviousMonitorState $PreviousState 'DefenderMonitor')
    $monitorResults += Invoke-PowerSentryXUserMonitor -PreviousState @(Get-PreviousMonitorState $PreviousState 'UserMonitor')
    $monitorResults += Invoke-PowerSentryXServiceMonitor -PreviousState @(Get-PreviousMonitorState $PreviousState 'ServiceMonitor')
    $monitorResults += Invoke-PowerSentryXProcessMonitor -PreviousState @(Get-PreviousMonitorState $PreviousState 'ProcessMonitor')

    $lastEventCheck = $null
    if ($null -ne $PreviousState) {
        $lastEventProperty = $PreviousState.PSObject.Properties['LastEventCheckUtc']
        if ($null -ne $lastEventProperty) { $lastEventCheck = [datetime]$lastEventProperty.Value }
    }
    if ($null -eq $lastEventCheck) { $lastEventCheck = $checkedAtUtc.AddHours(-1) }

    $eventLogResult = Invoke-PowerSentryXEventLogMonitor -Since $lastEventCheck -LogName 'Security' -MaxEvents 100
    $monitorResults += $eventLogResult
    $eventFindings = @()

    if ($eventLogResult.Status -eq 'Success') {
        $eventMap = Get-PowerSentryXEventMap
        $classifications = @(Invoke-PowerSentryXEventClassifier -Events @($eventLogResult.Data.Events) -EventMap $eventMap)
        $eventFindings = @(Convert-PowerSentryXEventClassificationsToFindings -Classifications $classifications)
    }

    $findingSummary = Get-PowerSentryXFindingSummary -Findings $eventFindings

    return [pscustomobject]@{
        RunId = $runId
        Mode = 'Monitor'
        CheckedAtUtc = $checkedAtUtc
        MonitorResults = $monitorResults
        Findings = $eventFindings
        FindingSummary = $findingSummary
        NextState = [pscustomobject]@{
            Version = 1
            SavedAtUtc = $checkedAtUtc
            LastEventCheckUtc = $checkedAtUtc
            FirewallMonitor = @($monitorResults | Where-Object MonitorId -eq 'FirewallMonitor' | Select-Object -ExpandProperty CurrentState)
            DefenderMonitor = ($monitorResults | Where-Object MonitorId -eq 'DefenderMonitor' | Select-Object -ExpandProperty CurrentState)
            UserMonitor = @($monitorResults | Where-Object MonitorId -eq 'UserMonitor' | Select-Object -ExpandProperty CurrentState)
            ServiceMonitor = @($monitorResults | Where-Object MonitorId -eq 'ServiceMonitor' | Select-Object -ExpandProperty CurrentState)
            ProcessMonitor = @($monitorResults | Where-Object MonitorId -eq 'ProcessMonitor' | Select-Object -ExpandProperty CurrentState)
        }
    }
}

if ($Mode -eq 'Audit') {
    $context = Invoke-PowerSentryXAuditRun
    $reportDirectory = Join-Path -Path $PSScriptRoot -ChildPath $settings.Reporting.OutputDirectory
    $reportPath = Write-PowerSentryXJsonReport -AuditContext $context -OutputDirectory $reportDirectory -ErrorAction Stop
    $context | Add-Member -NotePropertyName ReportPath -NotePropertyValue $reportPath
    Write-PowerSentryXLog -Message "JSON report created: $reportPath" -Level 'INFO' -ErrorAction Stop
    return $context
}

$previousState = $null
if (Test-Path -LiteralPath $MonitorStatePath) {
    $previousState = Get-Content -LiteralPath $MonitorStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}

$monitorContexts = @()

for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
    $monitorContext = Invoke-PowerSentryXMonitorRun -PreviousState $previousState
    $reportDirectory = Join-Path -Path $PSScriptRoot -ChildPath $settings.Reporting.OutputDirectory
    $reportPath = Write-PowerSentryXJsonReport -AuditContext $monitorContext -OutputDirectory $reportDirectory -ErrorAction Stop
    $monitorContext | Add-Member -NotePropertyName ReportPath -NotePropertyValue $reportPath
    $monitorContexts += $monitorContext
    $previousState = $monitorContext.NextState

    $stateDirectory = Split-Path -Path $MonitorStatePath -Parent
    if (-not (Test-Path -LiteralPath $stateDirectory)) {
        New-Item -Path $stateDirectory -ItemType Directory -Force | Out-Null
    }
    $previousState | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $MonitorStatePath -Encoding utf8
    Write-PowerSentryXLog -Message "Monitor report created: $reportPath" -Level 'INFO' -ErrorAction Stop

    if ($iteration -lt $Iterations) {
        Start-Sleep -Seconds $MonitorIntervalSeconds
    }
}

return $monitorContexts
