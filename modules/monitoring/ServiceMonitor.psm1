function Invoke-PowerSentryXServiceMonitor {
    [CmdletBinding()]
    param (
        [array]$PreviousState = @()
    )

    $checkedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)

        $currentState = @(
            foreach ($service in $services) {
                [pscustomobject]@{
                    Name        = $service.Name
                    DisplayName = $service.DisplayName
                    State       = $service.State
                    StartMode   = $service.StartMode
                    StartName   = $service.StartName
                    PathName    = $service.PathName
                    ProcessId   = $service.ProcessId
                }
            }
        )

        $changes = @()
        $baselineAvailable = $PreviousState.Count -gt 0

        if ($baselineAvailable) {
            $previousByName = @{}
            $currentByName = @{}

            foreach ($previousService in $PreviousState) {
                $previousByName[$previousService.Name] = $previousService
            }

            foreach ($currentService in $currentState) {
                $currentByName[$currentService.Name] = $currentService

                if (-not $previousByName.ContainsKey($currentService.Name)) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Added'
                        ServiceName = $currentService.Name
                        Details     = 'A new Windows service was detected.'
                    }

                    continue
                }

                $previousService = $previousByName[$currentService.Name]

                if ($previousService.State -ne $currentService.State) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Modified'
                        ServiceName = $currentService.Name
                        Property    = 'State'
                        Previous    = $previousService.State
                        Current     = $currentService.State
                    }
                }

                if ($previousService.StartMode -ne $currentService.StartMode) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Modified'
                        ServiceName = $currentService.Name
                        Property    = 'StartMode'
                        Previous    = $previousService.StartMode
                        Current     = $currentService.StartMode
                    }
                }

                if ($previousService.StartName -ne $currentService.StartName) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Modified'
                        ServiceName = $currentService.Name
                        Property    = 'StartName'
                        Previous    = $previousService.StartName
                        Current     = $currentService.StartName
                    }
                }

                if ($previousService.PathName -ne $currentService.PathName) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Modified'
                        ServiceName = $currentService.Name
                        Property    = 'PathName'
                        Previous    = $previousService.PathName
                        Current     = $currentService.PathName
                    }
                }
            }

            foreach ($previousService in $PreviousState) {
                if (-not $currentByName.ContainsKey($previousService.Name)) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Removed'
                        ServiceName = $previousService.Name
                        Details     = 'A Windows service is missing from the current state.'
                    }
                }
            }
        }

        return [pscustomobject]@{
            MonitorId         = 'ServiceMonitor'
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
            MonitorId         = 'ServiceMonitor'
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

Export-ModuleMember -Function Invoke-PowerSentryXServiceMonitor