function Invoke-PowerSentryXSecurityPolicyAuditCollector {
    [CmdletBinding()]
    param ()

    $collectedAtUtc = (Get-Date).ToUniversalTime()

    try {
        $auditPolPath = Join-Path `
            -Path $env:SystemRoot `
            -ChildPath 'System32/auditpol.exe'

        if (-not (Test-Path -LiteralPath $auditPolPath)) {
            throw 'The auditpol.exe command was not found.'
        }

        $auditPolicyOutput = @(
            & $auditPolPath /get /category:* 2>&1 |
                ForEach-Object { "$_" }
        )

        if ($LASTEXITCODE -ne 0) {
            throw "auditpol.exe returned exit code $LASTEXITCODE."
        }

        $data = [pscustomobject]@{
            AuditPolicyLines = $auditPolicyOutput
            TotalLines       = $auditPolicyOutput.Count
        }

        return [pscustomobject]@{
            CollectorId    = 'SecurityPolicyAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Success'
            Data           = $data
            Errors         = @()
        }
    }
    catch {
        return [pscustomobject]@{
            CollectorId    = 'SecurityPolicyAudit'
            CollectedAtUtc = $collectedAtUtc
            Status         = 'Error'
            Data           = @()
            Errors         = @(
                $_.Exception.Message
            )
        }
    }
}

Export-ModuleMember -Function Invoke-PowerSentryXSecurityPolicyAuditCollector