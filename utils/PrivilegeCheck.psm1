function Test-PowerSentryXAdministrator {
    [CmdletBinding()]
    param ()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    try {
        $principal = [System.Security.Principal.WindowsPrincipal]::new(
            $identity
        )

        return $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }

    finally {
        $identity.Dispose()
    }
}

Export-ModuleMember -Function Test-PowerSentryXAdministrator