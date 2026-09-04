function Invoke-PowerSentryXProcessAuditCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $processes = @(Get-Process -ErrorAction Stop)

        $processData = @(
            foreach ($process in $processes) {
                $path = 'Unknown'
                $startTime = $null

                try {
                    $path = $process.Path
                }
                catch {
                    $path = 'Unknown'
                }

                try {
                    $startTime = $process.StartTime.ToUniversalTime()
                }
                catch {
                    $startTime = $null
                }

                [pscustomobject]@{
                    ProcessId   = $process.Id
                    ProcessName = $process.ProcessName
                    Path        = $path
                    StartTimeUtc = $startTime
                    SessionId   = $process.SessionId
                    Responding  = $process.Responding
                }
            }
        )

        $data = [pscustomobject]@{
            Processes = $processData
            TotalCount = $processData.Count
        }

        return [pscustomobject]@{
            CollectorId    = 'ProcessAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Success'
            Data           = $data
            Errors         = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId    = 'ProcessAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Error'
            Data           = @()
            Errors         = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXProcessAuditCollector