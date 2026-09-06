function Invoke-PowerSentryXFirewallMonitor {
    [CmdletBinding()]
    param (
        [array]$PreviousState = @()
    )

    $checkedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

        $currentState = @(
            foreach ($profile in $profiles) {
                [pscustomobject]@{
                    ProfileName              = $profile.Name
                    Enabled                  = $profile.Enabled
                    DefaultInboundAction    = $profile.DefaultInboundAction
                    DefaultOutboundAction   = $profile.DefaultOutboundAction
                    AllowInboundRules       = $profile.AllowInboundRules
                    AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
                    NotifyOnListen           = $profile.NotifyOnListen
                }
            }
        )

        $changes = @()
        $baselineAvailable = $PreviousState.Count -gt 0

        if ($baselineAvailable) {
            $previousByName = @{}

            foreach ($previousProfile in $PreviousState) {
                $previousByName[$previousProfile.ProfileName] = $previousProfile
            }

            foreach ($currentProfile in $currentState) {
                if (-not $previousByName.ContainsKey($currentProfile.ProfileName)) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Added'
                        ProfileName = $currentProfile.ProfileName
                        Details     = 'Firewall profile appeared in the current state.'
                    }

                    continue
                }

                $previousProfile = $previousByName[$currentProfile.ProfileName]

                if ($previousProfile.Enabled -ne $currentProfile.Enabled) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Modified'
                        ProfileName = $currentProfile.ProfileName
                        Property    = 'Enabled'
                        Previous    = $previousProfile.Enabled
                        Current     = $currentProfile.Enabled
                    }
                }

                if ($previousProfile.DefaultInboundAction -ne $currentProfile.DefaultInboundAction) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Modified'
                        ProfileName = $currentProfile.ProfileName
                        Property    = 'DefaultInboundAction'
                        Previous    = $previousProfile.DefaultInboundAction
                        Current     = $currentProfile.DefaultInboundAction
                    }
                }

                if ($previousProfile.DefaultOutboundAction -ne $currentProfile.DefaultOutboundAction) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Modified'
                        ProfileName = $currentProfile.ProfileName
                        Property    = 'DefaultOutboundAction'
                        Previous    = $previousProfile.DefaultOutboundAction
                        Current     = $currentProfile.DefaultOutboundAction
                    }
                }
            }

            foreach ($previousProfile in $PreviousState) {
                $stillExists = @(
                    $currentState |
                        Where-Object {
                            $_.ProfileName -eq $previousProfile.ProfileName
                        }
                )

                if ($stillExists.Count -eq 0) {
                    $changes += [pscustomobject]@{
                        ChangeType  = 'Removed'
                        ProfileName = $previousProfile.ProfileName
                        Details     = 'Firewall profile is missing from the current state.'
                    }
                }
            }
        }

        return [pscustomobject]@{
            MonitorId          = 'FirewallMonitor'
            CheckedAtUtc       = $checkedAtUtc
            Status             = 'Success'
            BaselineAvailable  = $baselineAvailable
            CurrentState       = $currentState
            Changes            = $changes
            Errors             = @()
        }
    }
    catch {
        return [pscustomobject]@{
            MonitorId          = 'FirewallMonitor'
            CheckedAtUtc       = $checkedAtUtc
            Status             = 'Error'
            BaselineAvailable  = $false
            CurrentState       = @()
            Changes            = @()
            Errors             = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXFirewallMonitor