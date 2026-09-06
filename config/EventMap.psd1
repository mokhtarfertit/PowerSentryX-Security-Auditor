@{
    'Security:4625' = @{
        RuleId         = 'EVT-4625'
        Category       = 'Authentication'
        Severity       = 'WARNING'
        Summary        = 'A failed logon attempt was recorded.'
        Recommendation = 'Review the account, source address, and frequency of failed attempts.'
    }

    'Security:4720' = @{
        RuleId         = 'EVT-4720'
        Category       = 'UserManagement'
        Severity       = 'WARNING'
        Summary        = 'A user account was created.'
        Recommendation = 'Verify that the account creation was authorized.'
    }

    'Security:4732' = @{
        RuleId         = 'EVT-4732'
        Category       = 'PrivilegeManagement'
        Severity       = 'WARNING'
        Summary        = 'A member was added to a local security group.'
        Recommendation = 'Verify that the membership change was authorized.'
    }

    'Security:1102' = @{
        RuleId         = 'EVT-1102'
        Category       = 'Audit'
        Severity       = 'CRITICAL'
        Summary        = 'The Security event log was cleared.'
        Recommendation = 'Investigate the event immediately and verify the reason for clearing the log.'
    }

    'System:7045' = @{
        RuleId         = 'EVT-7045'
        Category       = 'Service'
        Severity       = 'WARNING'
        Summary        = 'A new service was installed.'
        Recommendation = 'Verify that the service installation was authorized.'
    }
}