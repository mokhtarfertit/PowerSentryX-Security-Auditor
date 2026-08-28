function Get-PowerSentryXSettings {
    [CmdletBinding()]
    param (
        [string]$Path = (
            Join-Path -Path $PSScriptRoot -ChildPath '../config/settings.psd1'
        )
    )

    $settings = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop

    return $settings

}

Export-ModuleMember -Function Get-PowerSentryXSettings