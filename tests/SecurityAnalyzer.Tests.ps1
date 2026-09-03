$modulePath = Join-Path `
    -Path $PSScriptRoot `
    -ChildPath '../modules/analysis/SecurityAnalyzer.psm1'

Import-Module -Name $modulePath -Force

Describe 'Invoke-PowerSentryXSecurityAnalyzer' {

    It 'returns a Pass finding for an enabled firewall profile' {
        $collectorResults = @(
            [pscustomobject]@{
                CollectorId   = 'Firewall'
                Status        = 'Success'
                CollectedAtUtc = (Get-Date).ToUniversalTime()
                Data          = @(
                    [pscustomobject]@{
                        ProfileName = 'Public'
                        Enabled     = $true
                    }
                )
                Errors = @()
            }
        )

        $findings = @(Invoke-PowerSentryXSecurityAnalyzer -CollectorResults $collectorResults)

        $findings.Count | Should -Be 1
        $findings[0].Outcome | Should -Be 'Pass'
        $findings[0].Severity | Should -Be 'INFO'
        $findings[0].ResourceId | Should -Be 'Firewall/Public'
    }

    It 'returns a Critical finding for a disabled firewall profile' {
        $collectorResults = @(
            [pscustomobject]@{
                CollectorId   = 'Firewall'
                Status        = 'Success'
                CollectedAtUtc = (Get-Date).ToUniversalTime()
                Data          = @(
                    [pscustomobject]@{
                        ProfileName = 'Private'
                        Enabled     = $false
                    }
                )
                Errors = @()
            }
        )

        $findings = @(Invoke-PowerSentryXSecurityAnalyzer -CollectorResults $collectorResults)

        $findings.Count | Should -Be 1
        $findings[0].Outcome | Should -Be 'Fail'
        $findings[0].Severity | Should -Be 'CRITICAL'
    }

    It 'returns an Unknown finding when firewall collection fails' {
        $collectorResults = @(
            [pscustomobject]@{
                CollectorId   = 'Firewall'
                Status        = 'Error'
                CollectedAtUtc = (Get-Date).ToUniversalTime()
                Data          = @()
                Errors        = @('Access was denied.')
            }
        )

        $findings = @(Invoke-PowerSentryXSecurityAnalyzer -CollectorResults $collectorResults)

        $findings.Count | Should -Be 1
        $findings[0].Outcome | Should -Be 'Unknown'
        $findings[0].Severity | Should -Be 'WARNING'
        $findings[0].Evidence | Should -Contain 'Access was denied.'
    }

    It 'ignores collectors that are not Firewall collectors' {
        $collectorResults = @(
            [pscustomobject]@{
                CollectorId   = 'SystemInfo'
                Status        = 'Success'
                CollectedAtUtc = (Get-Date).ToUniversalTime()
                Data          = @()
                Errors         = @()
            }
        )

        $findings = @(Invoke-PowerSentryXSecurityAnalyzer -CollectorResults $collectorResults)

        $findings.Count | Should -Be 0
    }
}