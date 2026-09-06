function Get-PowerSentryXSettings {
    [CmdletBinding()]
    param (
        [string]$Path = (
            Join-Path `
                -Path $PSScriptRoot `
                -ChildPath '../config/settings.psd1'
        )
    )

    return Import-PowerShellDataFile `
        -LiteralPath $Path `
        -ErrorAction Stop
}

function Get-PowerSentryXEventMap {
    [CmdletBinding()]
    param (
        [string]$Path = (
            Join-Path `
                -Path $PSScriptRoot `
                -ChildPath '../config/EventMap.psd1'
        )
    )

    return Import-PowerShellDataFile `
        -LiteralPath $Path `
        -ErrorAction Stop
}

Export-ModuleMember -Function `
    Get-PowerSentryXSettings, `
    Get-PowerSentryXEventMap