$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../modules/analysis/StateComparator.psm1'
Import-Module -Name $modulePath -Force

Describe 'Compare-PowerSentryXState' {
    It 'detects added, removed, and modified state' {
        $previous = @(
            [pscustomobject]@{ Name = 'Existing'; Enabled = $false }
            [pscustomobject]@{ Name = 'Removed'; Enabled = $true }
        )

        $current = @(
            [pscustomobject]@{ Name = 'Existing'; Enabled = $true }
            [pscustomobject]@{ Name = 'Added'; Enabled = $true }
        )

        $result = Compare-PowerSentryXState -PreviousState $previous -CurrentState $current -IdentityProperty 'Name'

        $result.HasChanges | Should Be $true
        $result.Added.Count | Should Be 1
        $result.Removed.Count | Should Be 1
        $result.Modified.Count | Should Be 1
        $result.Modified[0].Property | Should Be 'Enabled'
    }
}
