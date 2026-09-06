function Invoke-PowerSentryXDefenderMonitor {
    [CmdletBinding()]
    param (
        [psobject]$PreviousState = $null
    )

    $checkedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop

        $currentState = [pscustomobject]@{
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

        $changes = @()
        $baselineAvailable = $null -ne $PreviousState

        if ($baselineAvailable) {
            $booleanProperties = @(
                'AntivirusEnabled'
                'RealTimeProtectionEnabled'
                'BehaviorMonitorEnabled'
                'IoavProtectionEnabled'
                'NetworkInspectionEnabled'
                'AntimalwareServiceEnabled'
            )

            foreach ($propertyName in $booleanProperties) {
                $previousValue = $PreviousState.$propertyName
                $currentValue = $currentState.$propertyName

                if ($previousValue -ne $currentValue) {
                    $changes += [pscustomobject]@{
                        ChangeType = 'Modified'
                        Property   = $propertyName
                        Previous   = $previousValue
                        Current    = $currentValue
                    }
                }
            }

            if ($PreviousState.AntivirusSignatureVersion -ne
                $currentState.AntivirusSignatureVersion) {
                $changes += [pscustomobject]@{
                    ChangeType = 'Modified'
                    Property   = 'AntivirusSignatureVersion'
                    Previous   = $PreviousState.AntivirusSignatureVersion
                    Current    = $currentState.AntivirusSignatureVersion
                }
            }

            if ($PreviousState.AntivirusSignatureLastUpdated -ne
                $currentState.AntivirusSignatureLastUpdated) {
                $changes += [pscustomobject]@{
                    ChangeType = 'Modified'
                    Property   = 'AntivirusSignatureLastUpdated'
                    Previous   = $PreviousState.AntivirusSignatureLastUpdated
                    Current    = $currentState.AntivirusSignatureLastUpdated
                }
            }
        }

        return [pscustomobject]@{
            MonitorId         = 'DefenderMonitor'
            CheckedAtUtc      = $checkedAtUtc
            Status            = 'Success'
            BaselineAvailable = $baselineAvailable
            CurrentState      = $currentState
            Changes           = $changes
            Errors            = @()
        }
    }
    catch {
        return [pscustomobject]@{
            MonitorId         = 'DefenderMonitor'
            CheckedAtUtc      = $checkedAtUtc
            Status            = 'Error'
            BaselineAvailable = $false
            CurrentState      = $null
            Changes           = @()
            Errors            = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXDefenderMonitor