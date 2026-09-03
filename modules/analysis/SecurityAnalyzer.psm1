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
                RuleId       = 'FW-001'
                Category     = 'Firewall'
                ResourceId   = 'Firewall'
                Outcome      = 'Unknown'
                Severity     = 'WARNING'
                Summary      = 'Firewall information could not be collected.'
                Evidence     = $collectorResult.Errors
                Recommendation = 'Run the audit with sufficient permissions and verify Windows Firewall availability.'
            }

            continue
        }

        foreach ($profile in $collectorResult.Data) {
            $resourceId = "Firewall/$($profile.ProfileName)"

            if ($profile.Enabled -eq $true) {
                $findings += [pscustomobject]@{
                    RuleId       = 'FW-001'
                    Category     = 'Firewall'
                    ResourceId   = $resourceId
                    Outcome      = 'Pass'
                    Severity     = 'INFO'
                    Summary      = "$($profile.ProfileName) firewall profile is enabled."
                    Evidence     = [pscustomobject]@{
                        Enabled = $profile.Enabled
                    }
                    Recommendation = ''
                }
            }
            elseif ($profile.Enabled -eq $false) {
                $findings += [pscustomobject]@{
                    RuleId       = 'FW-001'
                    Category     = 'Firewall'
                    ResourceId   = $resourceId
                    Outcome      = 'Fail'
                    Severity     = 'CRITICAL'
                    Summary      = "$($profile.ProfileName) firewall profile is disabled."
                    Evidence     = [pscustomobject]@{
                        Enabled = $profile.Enabled
                    }
                    Recommendation = 'Enable the firewall profile after confirming that required network traffic will continue to work.'
                }
            }
            else {
                $findings += [pscustomobject]@{
                    RuleId       = 'FW-001'
                    Category     = 'Firewall'
                    ResourceId   = $resourceId
                    Outcome      = 'Unknown'
                    Severity     = 'WARNING'
                    Summary      = "$($profile.ProfileName) firewall state could not be determined."
                    Evidence     = [pscustomobject]@{
                        Enabled = $profile.Enabled
                    }
                    Recommendation = 'Verify the firewall profile manually.'
                }
            }
        }
    }

    return $findings
}

Export-ModuleMember -Function Invoke-PowerSentryXSecurityAnalyzer