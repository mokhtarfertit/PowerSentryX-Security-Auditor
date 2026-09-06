function Invoke-PowerSentryXUserMonitor {
    [CmdletBinding()]
    param (
        [array]$PreviousState = @()
    )

    $checkedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $users = @(Get-LocalUser -ErrorAction Stop)

        $currentState = @(
            foreach ($user in $users) {
                [pscustomobject]@{
                    Name             = $user.Name
                    Enabled          = $user.Enabled
                    Description      = $user.Description
                    LastLogon        = $user.LastLogon
                    PasswordRequired = $user.PasswordRequired
                    PasswordExpires  = $user.PasswordExpires
                    SID              = $user.SID.Value
                }
            }
        )

        $changes = @()
        $baselineAvailable = $PreviousState.Count -gt 0

        if ($baselineAvailable) {
            $previousByName = @{}

            foreach ($previousUser in $PreviousState) {
                $previousByName[$previousUser.Name] = $previousUser
            }

            $currentByName = @{}

            foreach ($currentUser in $currentState) {
                $currentByName[$currentUser.Name] = $currentUser

                if (-not $previousByName.ContainsKey($currentUser.Name)) {
                    $changes += [pscustomobject]@{
                        ChangeType = 'Added'
                        UserName   = $currentUser.Name
                        Details    = 'A new local user account was detected.'
                    }

                    continue
                }

                $previousUser = $previousByName[$currentUser.Name]

                if ($previousUser.Enabled -ne $currentUser.Enabled) {
                    $changes += [pscustomobject]@{
                        ChangeType = 'Modified'
                        UserName   = $currentUser.Name
                        Property   = 'Enabled'
                        Previous   = $previousUser.Enabled
                        Current    = $currentUser.Enabled
                    }
                }
            }

            foreach ($previousUser in $PreviousState) {
                if (-not $currentByName.ContainsKey($previousUser.Name)) {
                    $changes += [pscustomobject]@{
                        ChangeType = 'Removed'
                        UserName   = $previousUser.Name
                        Details    = 'A local user account is missing from the current state.'
                    }
                }
            }
        }

        return [pscustomobject]@{
            MonitorId         = 'UserMonitor'
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
            MonitorId         = 'UserMonitor'
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

Export-ModuleMember -Function Invoke-PowerSentryXUserMonitor