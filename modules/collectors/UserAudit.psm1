function Invoke-PowerSentryXUserAuditCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $users = @(Get-LocalUser -ErrorAction Stop)

        $administratorSid = [System.Security.Principal.SecurityIdentifier]::new(
            'S-1-5-32-544'
        )

        $administratorMembers = @(
            Get-LocalGroupMember -SID $administratorSid -ErrorAction Stop
        )

        $userData = @(
            foreach ($user in $users) {
                [pscustomobject]@{
                    Name              = $user.Name
                    Enabled           = $user.Enabled
                    Description       = $user.Description
                    LastLogon         = $user.LastLogon
                    PasswordRequired  = $user.PasswordRequired
                    PasswordExpires   = $user.PasswordExpires
                    PrincipalSource   = $user.PrincipalSource
                    SID               = $user.SID.Value
                }
            }
        )

        $administratorData = @(
            foreach ($member in $administratorMembers) {
                [pscustomobject]@{
                    Name            = $member.Name
                    ObjectClass     = $member.ObjectClass
                    PrincipalSource = $member.PrincipalSource
                    SID             = $member.SID.Value
                }
            }
        )

        $guestAccount = $users |
            Where-Object { $_.Name -eq 'Guest' } |
            Select-Object -First 1

        $guestEnabled = $null

        if ($null -ne $guestAccount) {
            $guestEnabled = $guestAccount.Enabled
        }

        $data = [pscustomobject]@{
            LocalUsers          = $userData
            DisabledAccounts    = @(
                $userData | Where-Object { $_.Enabled -eq $false }
            )
            GuestAccountEnabled = $guestEnabled
            Administrators      = $administratorData
        }

        return [pscustomobject]@{
            CollectorId    = 'UserAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Success'
            Data           = $data
            Errors         = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId    = 'UserAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Error'
            Data           = @()
            Errors         = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXUserAuditCollector