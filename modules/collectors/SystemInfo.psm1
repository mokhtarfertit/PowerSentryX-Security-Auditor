function Invoke-PowerSentryXSystemInfoCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $operatingSystem = Get-CimInstance `
            -ClassName Win32_OperatingSystem `
            -ErrorAction Stop

        $computerSystem = Get-CimInstance `
            -ClassName Win32_ComputerSystem `
            -ErrorAction Stop

        $lastBootTimeUtc = $operatingSystem.LastBootUpTime.ToUniversalTime()
        $uptime = $collectedAtUtc - $lastBootTimeUtc

        $data = [pscustomobject]@{
            ComputerName      = $env:COMPUTERNAME
            OperatingSystem   = $operatingSystem.Caption
            OperatingSystemVersion = $operatingSystem.Version
            Architecture      = $operatingSystem.OSArchitecture
            CurrentUser       = "$env:USERDOMAIN\$env:USERNAME"
            Domain            = $computerSystem.Domain
            LastBootTimeUtc   = $lastBootTimeUtc
            Uptime            = $uptime
        }

        return [pscustomobject]@{
            CollectorId  = 'SystemInfo'
            CollectedAtUtc = $collectedAtUtc
            Status       = 'Success'
            Data         = $data
            Errors       = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId  = 'SystemInfo'
            CollectedAtUtc = $collectedAtUtc
            Status       = 'Error'
            Data         = $null
            Errors       = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXSystemInfoCollector