function Write-PowerSentryXLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO',
        
        [string]$LogPath = (
            Join-Path `
                -Path $PSScriptRoot `
                -ChildPath '../logs/application/powersentryx.log'
        )
    )

    $logDirectory = Split-Path -Path $LogPath -Parent

    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | 
            Out-Null
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString('o')
    $logEntry = "$timestamp [$Level] $Message"

    Add-Content -LiteralPath $LogPath -Value $logEntry -Encoding UTF8
}

Export-ModuleMember -Function Write-PowerSentryXLog