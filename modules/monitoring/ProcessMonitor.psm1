function Invoke-PowerSentryXProcessMonitor {
    [CmdletBinding()]
    param (
        [array]$PreviousState = @()
    )

    $checkedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $processes = @(Get-Process -ErrorAction Stop)

        $currentState = @(
            foreach ($process in $processes) {
                $path = 'Unknown'
                $startTimeUtc = $null

                try {
                    $path = $process.Path
                }
                catch {
                    $path = 'Unknown'
                }

                try {
                    $startTimeUtc = $process.StartTime.ToUniversalTime()
                }
                catch {
                    $startTimeUtc = $null
                }

                [pscustomobject]@{
                    ProcessId    = $process.Id
                    ProcessName  = $process.ProcessName
                    Path         = $path
                    StartTimeUtc = $startTimeUtc
                    SessionId    = $process.SessionId
                }
            }
        )

        $changes = @()
        $baselineAvailable = $PreviousState.Count -gt 0

        if ($baselineAvailable) {
            $previousById = @{}
            $currentById = @{}

            foreach ($previousProcess in $PreviousState) {
                $previousById[$previousProcess.ProcessId] = $previousProcess
            }

            foreach ($currentProcess in $currentState) {
                $currentById[$currentProcess.ProcessId] = $currentProcess

                if (-not $previousById.ContainsKey($currentProcess.ProcessId)) {
                    $changes += [pscustomobject]@{
                        ChangeType = 'Started'
                        ProcessId  = $currentProcess.ProcessId
                        ProcessName = $currentProcess.ProcessName
                        Path       = $currentProcess.Path
                    }

                    continue
                }

                $previousProcess = $previousById[$currentProcess.ProcessId]

                if ($previousProcess.ProcessName -ne $currentProcess.ProcessName) {
                    $changes += [pscustomobject]@{
                        ChangeType = 'ReusedProcessId'
                        ProcessId  = $currentProcess.ProcessId
                        Property   = 'ProcessName'
                        Previous   = $previousProcess.ProcessName
                        Current    = $currentProcess.ProcessName
                    }
                }

                if ($previousProcess.Path -ne $currentProcess.Path) {
                    $changes += [pscustomobject]@{
                        ChangeType = 'Modified'
                        ProcessId  = $currentProcess.ProcessId
                        ProcessName = $currentProcess.ProcessName
                        Property   = 'Path'
                        Previous   = $previousProcess.Path
                        Current    = $currentProcess.Path
                    }
                }
            }

            foreach ($previousProcess in $PreviousState) {
                if (-not $currentById.ContainsKey($previousProcess.ProcessId)) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Stopped'
                        ProcessId   = $previousProcess.ProcessId
                        ProcessName = $previousProcess.ProcessName
                        Path        = $previousProcess.Path
                    }
                }
            }
        }

        return [pscustomobject]@{
            MonitorId         = 'ProcessMonitor'
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
            MonitorId         = 'ProcessMonitor'
            CheckedAtUtc      = $checkedAtUtc
            Status            = 'Error'
            BaselineAvailable = $false
            CurrentState      = @()
            Changes           = @()
            Errors            = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXProcessMonitor