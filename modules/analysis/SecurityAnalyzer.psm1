function Invoke-PowerSentryXFirewallAnalyzer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$CollectorResults
    )

    $findings = @()

    foreach ($collectorResult in $CollectorResults) {
        if ($collectorResult.CollectorId -ne 'Firewall') {
            continue
        }

        if ($collectorResult.Status -ne 'Success') {
            $findings += [pscustomobject]@{
                RuleId         = 'FW-001'
                Category       = 'Firewall'
                ResourceId     = 'Firewall'
                Outcome        = 'Unknown'
                Severity        = 'WARNING'
                Summary        = 'Firewall information could not be collected.'
                Evidence       = $collectorResult.Errors
                Recommendation = 'Run the audit with sufficient permissions and verify Windows Firewall availability.'
            }

            continue
        }

        foreach ($profile in $collectorResult.Data) {
            $resourceId = "Firewall/$($profile.ProfileName)"

            if ($profile.Enabled -eq $true) {
                $findings += [pscustomobject]@{
                    RuleId         = 'FW-001'
                    Category       = 'Firewall'
                    ResourceId     = $resourceId
                    Outcome        = 'Pass'
                    Severity        = 'INFO'
                    Summary        = "$($profile.ProfileName) firewall profile is enabled."
                    Evidence       = [pscustomobject]@{
                        Enabled = $profile.Enabled
                    }
                    Recommendation = ''
                }
            }
            elseif ($profile.Enabled -eq $false) {
                $findings += [pscustomobject]@{
                    RuleId         = 'FW-001'
                    Category       = 'Firewall'
                    ResourceId     = $resourceId
                    Outcome        = 'Fail'
                    Severity        = 'CRITICAL'
                    Summary        = "$($profile.ProfileName) firewall profile is disabled."
                    Evidence       = [pscustomobject]@{
                        Enabled = $profile.Enabled
                    }
                    Recommendation = 'Enable the firewall profile after confirming that required network traffic will continue to work.'
                }
            }
            else {
                $findings += [pscustomobject]@{
                    RuleId         = 'FW-001'
                    Category       = 'Firewall'
                    ResourceId     = $resourceId
                    Outcome        = 'Unknown'
                    Severity        = 'WARNING'
                    Summary        = "$($profile.ProfileName) firewall state could not be determined."
                    Evidence       = [pscustomobject]@{
                        Enabled = $profile.Enabled
                    }
                    Recommendation = 'Verify the firewall profile manually.'
                }
            }
        }
    }

    return $findings
}

function Invoke-PowerSentryXSecurityAnalyzer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$CollectorResults
    )

    $findings = @(Invoke-PowerSentryXFirewallAnalyzer -CollectorResults $CollectorResults)

    foreach ($collectorResult in $CollectorResults) {
        if ($collectorResult.CollectorId -eq 'Firewall') {
            continue
        }

        if ($collectorResult.Status -ne 'Success') {
            $findings += [pscustomobject]@{
                RuleId         = "$($collectorResult.CollectorId)-000"
                Category       = $collectorResult.CollectorId
                ResourceId     = $collectorResult.CollectorId
                Outcome        = 'Unknown'
                Severity       = 'WARNING'
                Summary        = "$($collectorResult.CollectorId) information could not be collected."
                Evidence       = $collectorResult.Errors
                Recommendation = 'Review the collection error and run the check with the required Windows permissions.'
            }
            continue
        }

        switch ($collectorResult.CollectorId) {
            'UserAudit' {
                $userData = $collectorResult.Data

                if ($userData.GuestAccountEnabled -eq $true) {
                    $findings += [pscustomobject]@{
                        RuleId = 'USR-001'; Category = 'UserManagement'; ResourceId = 'User/Guest'
                        Outcome = 'Fail'; Severity = 'CRITICAL'
                        Summary = 'The built-in Guest account is enabled.'
                        Evidence = [pscustomobject]@{ Enabled = $true }
                        Recommendation = 'Disable the Guest account unless there is a documented operational requirement.'
                    }
                }
                elseif ($userData.GuestAccountEnabled -eq $false) {
                    $findings += [pscustomobject]@{
                        RuleId = 'USR-001'; Category = 'UserManagement'; ResourceId = 'User/Guest'
                        Outcome = 'Pass'; Severity = 'INFO'
                        Summary = 'The built-in Guest account is disabled.'
                        Evidence = [pscustomobject]@{ Enabled = $false }
                        Recommendation = ''
                    }
                }

                $disabledAccounts = @($userData.DisabledAccounts)
                if ($disabledAccounts.Count -gt 0) {
                    $findings += [pscustomobject]@{
                        RuleId = 'USR-002'; Category = 'UserManagement'; ResourceId = 'User/DisabledAccounts'
                        Outcome = 'Pass'; Severity = 'INFO'
                        Summary = "$($disabledAccounts.Count) disabled local account(s) were found."
                        Evidence = $disabledAccounts
                        Recommendation = 'Review disabled accounts and remove obsolete accounts according to policy.'
                    }
                }

                $administrators = @($userData.Administrators)
                if ($administrators.Count -gt 0) {
                    $findings += [pscustomobject]@{
                        RuleId = 'USR-003'; Category = 'PrivilegeManagement'; ResourceId = 'User/Administrators'
                        Outcome = 'Pass'; Severity = 'INFO'
                        Summary = "$($administrators.Count) local administrator member(s) were found."
                        Evidence = $administrators
                        Recommendation = 'Compare administrator membership with an approved administrator list.'
                    }
                }
            }

            'DefenderAudit' {
                $defenderData = $collectorResult.Data
                $defenderChecks = @(
                    @{ Property = 'AntivirusEnabled'; Label = 'Antivirus' }
                    @{ Property = 'RealTimeProtectionEnabled'; Label = 'Real-time protection' }
                    @{ Property = 'BehaviorMonitorEnabled'; Label = 'Behavior monitoring' }
                    @{ Property = 'IoavProtectionEnabled'; Label = 'Downloaded-file scanning' }
                    @{ Property = 'NetworkInspectionEnabled'; Label = 'Network inspection' }
                    @{ Property = 'AntimalwareServiceEnabled'; Label = 'Antimalware service' }
                )

                foreach ($check in $defenderChecks) {
                    $value = $defenderData.($check.Property)
                    if ($value -eq $true) {
                        $findings += [pscustomobject]@{
                            RuleId = 'DEF-001'; Category = 'Defender'; ResourceId = "Defender/$($check.Property)"
                            Outcome = 'Pass'; Severity = 'INFO'
                            Summary = "$($check.Label) is enabled."
                            Evidence = [pscustomobject]@{ Enabled = $value }
                            Recommendation = ''
                        }
                    }
                    elseif ($value -eq $false) {
                        $findings += [pscustomobject]@{
                            RuleId = 'DEF-001'; Category = 'Defender'; ResourceId = "Defender/$($check.Property)"
                            Outcome = 'Fail'; Severity = 'CRITICAL'
                            Summary = "$($check.Label) is disabled."
                            Evidence = [pscustomobject]@{ Enabled = $value }
                            Recommendation = "Enable $($check.Label) and verify that the change is not caused by policy or a security product conflict."
                        }
                    }
                }
            }

            'NetworkAudit' {
                $ports = @($collectorResult.Data.ListeningPorts)
                $findings += [pscustomobject]@{
                    RuleId = 'NET-001'; Category = 'Network'; ResourceId = 'Network/ListeningPorts'
                    Outcome = 'Pass'; Severity = 'INFO'
                    Summary = "$($ports.Count) listening TCP port(s) were collected."
                    Evidence = $ports
                    Recommendation = 'Review listening ports against an approved service inventory.'
                }
            }

            'ProcessAudit' {
                $processes = @($collectorResult.Data.Processes)
                $unknownPaths = @($processes | Where-Object { $_.Path -eq 'Unknown' })
                if ($unknownPaths.Count -gt 0) {
                    $findings += [pscustomobject]@{
                        RuleId = 'PROC-001'; Category = 'Process'; ResourceId = 'Process/UnknownPaths'
                        Outcome = 'Unknown'; Severity = 'INFO'
                        Summary = "$($unknownPaths.Count) process executable path(s) could not be read."
                        Evidence = $unknownPaths
                        Recommendation = 'Repeat the audit with appropriate permissions if process path verification is required.'
                    }
                }
            }

            'ServiceAudit' {
                $services = @($collectorResult.Data.Services)
                $automaticServices = @($services | Where-Object { $_.StartMode -eq 'Auto' })
                $findings += [pscustomobject]@{
                    RuleId = 'SVC-001'; Category = 'Service'; ResourceId = 'Service/Automatic'
                    Outcome = 'Pass'; Severity = 'INFO'
                    Summary = "$($automaticServices.Count) automatically starting service(s) were collected."
                    Evidence = $automaticServices
                    Recommendation = 'Compare automatic services and their executable paths with an approved inventory.'
                }
            }

            'ScheduledTaskAudit' {
                $tasks = @($collectorResult.Data.ScheduledTasks)
                $findings += [pscustomobject]@{
                    RuleId = 'TASK-001'; Category = 'Persistence'; ResourceId = 'ScheduledTask/Inventory'
                    Outcome = 'Pass'; Severity = 'INFO'
                    Summary = "$($tasks.Count) scheduled task(s) were collected."
                    Evidence = $tasks
                    Recommendation = 'Review tasks that execute from user-writable locations or run with elevated privileges.'
                }
            }

            'SecurityPolicyAudit' {
                $findings += [pscustomobject]@{
                    RuleId = 'POL-001'; Category = 'SecurityPolicy'; ResourceId = 'SecurityPolicy/AuditPolicy'
                    Outcome = 'Pass'; Severity = 'INFO'
                    Summary = 'Windows audit policy information was collected.'
                    Evidence = $collectorResult.Data
                    Recommendation = 'Compare audit policy settings with the organization security baseline.'
                }
            }
        }
    }

    return $findings
}

function Get-PowerSentryXFindingSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    $allFindings = @($Findings)

    return [pscustomobject]@{
        Total    = $allFindings.Count
        Pass     = @($allFindings | Where-Object { $_.Outcome -eq 'Pass' }).Count
        Fail     = @($allFindings | Where-Object { $_.Outcome -eq 'Fail' }).Count
        Unknown  = @($allFindings | Where-Object { $_.Outcome -eq 'Unknown' }).Count
        Info     = @($allFindings | Where-Object { $_.Severity -eq 'INFO' }).Count
        Warning  = @($allFindings | Where-Object { $_.Severity -eq 'WARNING' }).Count
        Critical = @($allFindings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    }
}

function Convert-PowerSentryXEventClassificationsToFindings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Classifications
    )

    $findings = @()

    foreach ($classification in $Classifications) {
        if (-not $classification.Matched) {
            continue
        }

        $event = $classification.Event

        $resourceId = '{0}/{1}/{2}' -f `
            $classification.LogName,
            $classification.EventId,
            $event.RecordId

        $findings += [pscustomobject]@{
            RuleId         = $classification.RuleId
            Category       = $classification.Category
            ResourceId     = $resourceId
            Outcome        = 'Fail'
            Severity       = $classification.Severity
            Summary        = $classification.Summary
            Evidence       = [pscustomobject]@{
                EventId      = $event.EventId
                LogName      = $event.LogName
                RecordId     = $event.RecordId
                ProviderName = $event.ProviderName
                TimeCreated  = $event.TimeCreatedUtc
                Message      = $event.Message
            }
            Recommendation = $classification.Recommendation
        }
    }

    return $findings
}

Export-ModuleMember -Function Invoke-PowerSentryXSecurityAnalyzer, Invoke-PowerSentryXFirewallAnalyzer, Get-PowerSentryXFindingSummary, Convert-PowerSentryXEventClassificationsToFindings
