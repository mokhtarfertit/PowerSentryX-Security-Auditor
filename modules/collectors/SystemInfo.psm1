function Invoke-PowerSentryInfoCollector {
    [cmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $operatingSystem = Get-CimInstance `
            -ClassName Win32_OperatingSystem `
            -ErrorAction Stop
        
        $computerSystem = Get-CimInstance `
            -ClassName Win32_ComputerSystem
            -ErrorAction stop

        $lastBootTimeUtc = $operatingSystem.LastBootUpTime.ToUniversalTime()
        $uptime = $collectedAtUtc - $lastBootTimeUtc

        $data = [[PSCustomObject]@{
            ComputerName      = $env:COMPUTERNAME
            OperatingSystem   = $operatingSystem.Caption
            OperatingSystemVersion = $operatingSystem.Version
            Architecture      = $operatingSystem.OSArchitecture
            CurrentUser       = "$env:USERDOMAIN\$env:USERNAME"
            Domain            = $computerSystem.Domain
            LastBootTimeUtc   = $lastBootTimeUtc
            Uptime            = $uptime
        }]

    }
    catch {
        return [[PSCustomObject]@{
            CollectorId = 'SystemInfo'
            collectedAtUtc = $collectedAtUtc
            Status = 'Error'
            Data = $null
            Errors = @(
                $_.Exception.Message
            )
        }]
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXSystemInfoCollector