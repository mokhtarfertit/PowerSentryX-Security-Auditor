function Invoke-PowerSentryXDefenderAuditCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop

        $data = [pscustomobject]@{
            AntivirusEnabled              = $defenderStatus.AntivirusEnabled
            RealTimeProtectionEnabled     = $defenderStatus.RealTimeProtectionEnabled
            BehaviorMonitorEnabled        = $defenderStatus.BehaviorMonitorEnabled
            IoavProtectionEnabled         = $defenderStatus.IoavProtectionEnabled
            NetworkInspectionEnabled      = $defenderStatus.NISEnabled
            AntimalwareServiceEnabled     = $defenderStatus.AMServiceEnabled
            AntivirusSignatureVersion     = $defenderStatus.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
            QuickScanAge                  = $defenderStatus.QuickScanAge
            FullScanAge                   = $defenderStatus.FullScanAge
        }

        return [pscustomobject]@{
            CollectorId    = 'DefenderAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Success'
            Data           = $data
            Errors         = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId    = 'DefenderAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Error'
            Data           = @()
            Errors         = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXDefenderAuditCollector