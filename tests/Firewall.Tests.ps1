$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../modules/collectors/Firewall.psm1'

Import-Module -Name $modulePath -Force

Describe 'Invoke-PowerSentryXFirewallCollector' {

    It 'returns all firewall profiles when collection succeeds' {
        Mock Get-NetFirewallProfile {
            return @(
                [pscustomobject]@{
                    Name                   = 'Domain'
                    Enabled                = $true
                    DefaultInboundAction   = 'Block'
                    DefaultOutboundAction  = 'Allow'
                    AllowInboundRules      = $true
                    AllowLocalFirewallRules = $true
                    NotifyOnListen         = $true
                    LogFileName            = 'domain-firewall.log'
                    LogMaxSizeKilobytes    = 4096
                }

                [pscustomobject]@{
                    Name                   = 'Public'
                    Enabled                = $false
                    DefaultInboundAction   = 'Block'
                    DefaultOutboundAction  = 'Allow'
                    AllowInboundRules      = $false
                    AllowLocalFirewallRules = $false
                    NotifyOnListen         = $true
                    LogFileName            = 'public-firewall.log'
                    LogMaxSizeKilobytes    = 4096
                }
            )
        }

        $result = Invoke-PowerSentryXFirewallCollector

        $result.Status | Should -Be 'Success'
        $result.CollectorId | Should -Be 'Firewall'
        $result.Data.Count | Should -Be 2
        $result.Data[0].ProfileName | Should -Be 'Domain'
        $result.Data[0].Enabled | Should -Be $true
        $result.Data[1].ProfileName | Should -Be 'Public'
        $result.Data[1].Enabled | Should -Be $false
        $result.Errors.Count | Should -Be 0
    }

    It 'returns an Error result when firewall collection fails' {
        Mock Get-NetFirewallProfile {
            throw 'Firewall service is unavailable.'
        }

        $result = Invoke-PowerSentryXFirewallCollector

        $result.Status | Should -Be 'Error'
        $result.CollectorId | Should -Be 'Firewall'
        $result.Data.Count | Should -Be 0
        $result.Errors | Should -Contain 'Firewall service is unavailable.'
    }
}