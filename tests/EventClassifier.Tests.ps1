$classifierPath = Join-Path -Path $PSScriptRoot -ChildPath '../modules/analysis/EventClassifier.psm1'
Import-Module -Name $classifierPath -Force

Describe 'Invoke-PowerSentryXEventClassifier' {
    It 'classifies mapped events and preserves unmapped events' {
        $eventMap = @{
            'Security:4625' = @{
                RuleId = 'EVT-4625'
                Category = 'Authentication'
                Severity = 'WARNING'
                Summary = 'A failed logon attempt was recorded.'
                Recommendation = 'Review the failed logon.'
            }
        }

        $events = @(
            [pscustomobject]@{ EventId = 4625; LogName = 'Security'; RecordId = 1; Message = 'Failed logon.' }
            [pscustomobject]@{ EventId = 9999; LogName = 'Security'; RecordId = 2; Message = 'Unknown event.' }
        )

        $result = @(Invoke-PowerSentryXEventClassifier -Events $events -EventMap $eventMap)

        $result.Count | Should Be 2
        $result[0].Matched | Should Be $true
        $result[0].RuleId | Should Be 'EVT-4625'
        $result[1].Matched | Should Be $false
    }
}
