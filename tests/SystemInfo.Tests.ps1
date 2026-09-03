$modulePath = Join-Path `
    -Path $PSScriptRoot `
    -ChildPath '../modules/collectors/SystemInfo.psm1'

Import-Module -Name $modulePath -Force

Describe 'Invoke-PowerSentryXSystemInfoCollector' {

    It 'returns system information when CIM queries succeed' {
        Mock Get-CimInstance {
            param (
                $ClassName
            )

            if ($ClassName -eq 'Win32_OperatingSystem') {
                return [pscustomobject]@{
                    Caption        = 'Microsoft Windows Test'
                    Version        = '10.0.99999'
                    OSArchitecture = '64-bit'
                    LastBootUpTime = [datetime]'2026-09-01T08:00:00'
                }
            }

            if ($ClassName -eq 'Win32_ComputerSystem') {
                return [pscustomobject]@{
                    Domain = 'TESTDOMAIN'
                }
            }
        }

        $result = Invoke-PowerSentryXSystemInfoCollector

        $result.Status | Should -Be 'Success'
        $result.CollectorId | Should -Be 'SystemInfo'
        $result.Data.OperatingSystem | Should -Be 'Microsoft Windows Test'
        $result.Data.OperatingSystemVersion | Should -Be '10.0.99999'
        $result.Data.Architecture | Should -Be '64-bit'
        $result.Data.Domain | Should -Be 'TESTDOMAIN'
        $result.Errors.Count | Should -Be 0
    }

    It 'returns an Error result when CIM fails' {
        Mock Get-CimInstance {
            throw 'CIM service is unavailable.'
        }

        $result = Invoke-PowerSentryXSystemInfoCollector

        $result.Status | Should -Be 'Error'
        $result.CollectorId | Should -Be 'SystemInfo'
        $result.Data | Should -Be $null
        $result.Errors | Should -Contain 'CIM service is unavailable.'
    }
}