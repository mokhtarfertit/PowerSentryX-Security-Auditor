function Write-PowerSentryXJsonReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [psobject]$AuditContext,

        [Parameter(Mandatory)]
        [string]$OutputDirectory
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force |
            Out-Null
    }

    $fileName = "audit-$($AuditContext.RunId).json"
    $reportPath = Join-Path -Path $OutputDirectory -ChildPath $fileName

    $json = $AuditContext | ConvertTo-Json -Depth 10

    Set-Content `
        -LiteralPath $reportPath `
        -Value $json `
        -Encoding utf8

    return $reportPath
}

Export-ModuleMember -Function Write-PowerSentryXJsonReport