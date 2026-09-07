function Show-PowerSentryXBanner {
    [CmdletBinding()]
    param (
        [string]$Version = '0.1.0',
        [string]$Mode = 'Audit'
    )

    Write-Host ''
    Write-Host '=============================================' -ForegroundColor DarkCyan
    Write-Host '        PowerSentryX Security Auditor        ' -ForegroundColor Cyan
    Write-Host '=============================================' -ForegroundColor DarkCyan
    Write-Host "Version: $Version    Mode: $Mode" -ForegroundColor Gray
    Write-Host 'Read-only Windows security assessment' -ForegroundColor Gray
    Write-Host ''
}

function Show-PowerSentryXRunSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [psobject]$Context
    )

    $summary = $Context.FindingSummary

    if ($null -eq $summary) {
        return
    }

    Write-Host 'Run summary' -ForegroundColor Cyan
    Write-Host "  Mode:     $($Context.Mode)"

    if ($null -ne $Context.ReportPath) {
        Write-Host "  Report:   $($Context.ReportPath)"
    }

    Write-Host "  Findings: $($summary.Total)"
    Write-Host "  Critical: $($summary.Critical)" -ForegroundColor Red
    Write-Host "  Warning:  $($summary.Warning)" -ForegroundColor Yellow
    Write-Host "  Passed:   $($summary.Pass)" -ForegroundColor Green
    Write-Host ''
}

Export-ModuleMember -Function Show-PowerSentryXBanner, Show-PowerSentryXRunSummary
