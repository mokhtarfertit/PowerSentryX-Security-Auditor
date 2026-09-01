function Invoke-PowerSentryXFirewallCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

        $data = @(
            foreach ($profile in $profiles) {
                [pscustomobject]@{
                    ProfileName              = $profile.Name
                    Enabled                  = $profile.Enabled
                    DefaultInboundAction    = $profile.DefaultInboundAction
                    DefaultOutboundAction   = $profile.DefaultOutboundAction
                    AllowInboundRules       = $profile.AllowInboundRules
                    AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
                    NotifyOnListen           = $profile.NotifyOnListen
                    LogFileName              = $profile.LogFileName
                    LogMaxSizeKilobytes     = $profile.LogMaxSizeKilobytes
                }
            }
        )

        return [pscustomobject]@{
            CollectorId   = 'Firewall'
            CollectedAtUtc = $collectedAtUtc
            Status        = 'Success'
            Data          = $data
            Errors        = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId   = 'Firewall'
            CollectedAtUtc = $collectedAtUtc
            Status        = 'Error'
            Data          = @()
            Errors        = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXFirewallCollector