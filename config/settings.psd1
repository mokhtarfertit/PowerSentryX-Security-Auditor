@{
    # Collectors to run during on audit.
    EnabledCollectors = @(
        'SystemInfo'
        'Firewall'
        'UserAudit'
        'DefenderAudit'
        'NetworkAudit'
        'ProcessAudit'
        'ServiceAudit'
        'ScheduledTaskAudit'
        'SecurityPolicyAudit'
    )

    # Continue collecting  other results if one coller fails.
    ContinueOnCollectorError = $true

    Reporting = @{
        Format = 'Json'

        #Relatice to the project root.
        OutputDirectory = 'reports'
    }
}