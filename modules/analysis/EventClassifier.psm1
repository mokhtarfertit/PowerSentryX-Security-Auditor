function Invoke-PowerSentryXEventClassifier {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Events,

        [Parameter(Mandatory)]
        [hashtable]$EventMap
    )

    $classifications = @()

    foreach ($event in $Events) {
        $eventKey = '{0}:{1}' -f $event.LogName, $event.EventId

        if ($EventMap.ContainsKey($eventKey)) {
            $rule = $EventMap[$eventKey]

            $classifications += [pscustomobject]@{
                Matched        = $true
                EventId        = $event.EventId
                LogName        = $event.LogName
                RuleId         = $rule.RuleId
                Category       = $rule.Category
                Severity       = $rule.Severity
                Summary        = $rule.Summary
                Recommendation = $rule.Recommendation
                Event          = $event
            }
        }
        else {
            $classifications += [pscustomobject]@{
                Matched        = $false
                EventId        = $event.EventId
                LogName        = $event.LogName
                RuleId         = $null
                Category       = 'UnmappedEvent'
                Severity       = 'INFO'
                Summary        = 'No classification rule exists for this event.'
                Recommendation = ''
                Event          = $event
            }
        }
    }

    return $classifications
}

Export-ModuleMember -Function Invoke-PowerSentryXEventClassifier