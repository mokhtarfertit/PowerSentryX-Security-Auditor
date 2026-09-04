function Invoke-PowerSentryXScheduledTaskAuditCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        $taskData = @()
        $errors = @()

        foreach ($task in $tasks) {
            try {
                $taskInfo = Get-ScheduledTaskInfo `
                    -TaskName $task.TaskName `
                    -TaskPath $task.TaskPath `
                    -ErrorAction Stop

                $firstAction = @($task.Actions) | Select-Object -First 1

                $executePath = $null
                $arguments = $null

                if ($null -ne $firstAction) {
                    $executePath = $firstAction.Execute
                    $arguments = $firstAction.Arguments
                }

                $taskData += [pscustomobject]@{
                    TaskName       = $task.TaskName
                    TaskPath       = $task.TaskPath
                    State          = $task.State
                    Author         = $task.Author
                    Description    = $task.Description
                    UserId         = $task.Principal.UserId
                    RunLevel       = $task.Principal.RunLevel
                    Execute        = $executePath
                    Arguments      = $arguments
                    LastRunTime    = $taskInfo.LastRunTime
                    NextRunTime    = $taskInfo.NextRunTime
                    LastTaskResult = $taskInfo.LastTaskResult
                }
            }
            catch {
                $errors += "Could not inspect task '$($task.TaskPath)$($task.TaskName)': $($_.Exception.Message)"
            }
        }

        $status = 'Success'

        if ($errors.Count -gt 0) {
            $status = 'Partial'
        }

        $data = [pscustomobject]@{
            ScheduledTasks = $taskData
            TotalCount     = $taskData.Count
        }

        return [pscustomobject]@{
            CollectorId    = 'ScheduledTaskAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = $status
            Data           = $data
            Errors         = $errors
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId    = 'ScheduledTaskAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Error'
            Data           = @()
            Errors         = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXScheduledTaskAuditCollector