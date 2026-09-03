function Invoke-PowerSentryXNetworkAuditCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $connections = @(
            Get-NetTCPConnection -State Listen -ErrorAction Stop
        )

        $listeningPorts = @(
            foreach ($connection in $connections) {
                $processName = 'Unknown'

                try {
                    $process = Get-Process `
                        -Id $connection.OwningProcess `
                        -ErrorAction Stop

                    $processName = $process.ProcessName
                }
                catch {
                    $processName = 'Unknown'
                }

                [pscustomobject]@{
                    Protocol      = 'TCP'
                    LocalAddress  = $connection.LocalAddress
                    LocalPort     = $connection.LocalPort
                    State         = $connection.State
                    ProcessId     = $connection.OwningProcess
                    ProcessName   = $processName
                }
            }
        )

        $data = [pscustomobject]@{
            ListeningPorts = $listeningPorts
            TotalCount     = $listeningPorts.Count
        }

        return [pscustomobject]@{
            CollectorId    = 'NetworkAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Success'
            Data           = $data
            Errors         = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId    = 'NetworkAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Error'
            Data           = @()
            Errors         = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXNetworkAuditCollector