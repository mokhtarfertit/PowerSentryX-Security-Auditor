function Invoke-PowerSentryXEventLogMonitor {
    [CmdletBinding()]
    param (
        [datetime]$Since = (
            (Get-Date).ToUniversalTime().AddHours(-1)
        ),

        [string]$LogName = 'Security',

        [int]$MaxEvents = 100
    )

    $checkedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $events = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                StartTime = $Since
            } -MaxEvents $MaxEvents -ErrorAction Stop
        )

        $eventData = @(
            foreach ($event in $events) {
                $message = $null

                try {
                    $message = $event.Message
                }
                catch {
                    $message = 'Event message unavailable.'
                }

                [pscustomobject]@{
                    RecordId      = $event.RecordId
                    EventId       = $event.Id
                    ProviderName  = $event.ProviderName
                    LogName       = $event.LogName
                    TimeCreatedUtc = $event.TimeCreated.ToUniversalTime()
                    Level         = $event.LevelDisplayName
                    MachineName   = $event.MachineName
                    Message       = $message
                }
            }
        )

        $data = [pscustomobject]@{
            Events     = $eventData
            TotalCount = $eventData.Count
        }

        return [pscustomobject]@{
            MonitorId    = 'EventLogMonitor'
            CheckedAtUtc = $checkedAtUtc
            SinceUtc     = $Since.ToUniversalTime()
            Status       = 'Success'
            Data         = $data
            Errors       = @()
        }
    }
    catch {
        return [pscustomobject]@{
            MonitorId    = 'EventLogMonitor'
            CheckedAtUtc = $checkedAtUtc
            SinceUtc     = $Since.ToUniversalTime()
            Status       = 'Error'
            Data         = @()
            Errors       = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXEventLogMonitor