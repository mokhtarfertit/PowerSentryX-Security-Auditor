@{
    # Collectors to run during on audit.
    EnabledCollectors = @(
        'SystemInfo'
        'Firewall'
    )

    # Continue collecting  other results if one coller fails.
    ContinueOnCollectorError = $true

    Reporting = @{
        Format = 'Json'

        #Relatice to the project root.
        OutputDirectory = 'reports'
    }
}