function Invoke-PowerSentryXServiceAuditCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)

        $serviceData = @(
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

        $data = [pscustomobject]@{
            Services   = $serviceData
            TotalCount = $serviceData.Count
        }

        return [pscustomobject]@{
            CollectorId    = 'ServiceAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Success'
            Data           = $data
            Errors         = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId    = 'ServiceAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Error'
            Data           = @()
            Errors         = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXServiceAuditCollector