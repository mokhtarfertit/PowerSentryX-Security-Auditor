function Invoke-PowerSentryXSecurityAnalyzer {
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

function Get-PowerSentryXFindingSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
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

Export-ModuleMember -Function Invoke-PowerSentryXSecurityAnalyzer, Get-PowerSentryXFindingSummary, Convert-PowerSentryXEventClassificationsToFindings