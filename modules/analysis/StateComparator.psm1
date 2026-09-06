function Compare-PowerSentryXState {
    [CmdletBinding()]
    param (
        [array]$PreviousState = @(),

        [array]$CurrentState = @(),

        [Parameter(Mandatory)]
        [string]$IdentityProperty
    )

    $previousByKey = @{}
    $currentByKey = @{}

    foreach ($item in $PreviousState) {
        if ($item.PSObject.Properties.Name -notcontains $IdentityProperty) {
            throw "Previous state item is missing identity property '$IdentityProperty'."
        }

        $key = [string]$item.$IdentityProperty
        $previousByKey[$key] = $item
    }

    foreach ($item in $CurrentState) {
        if ($item.PSObject.Properties.Name -notcontains $IdentityProperty) {
            throw "Current state item is missing identity property '$IdentityProperty'."
        }

        $key = [string]$item.$IdentityProperty
        $currentByKey[$key] = $item
    }

    $added = @()
    $removed = @()
    $modified = @()

    foreach ($key in $currentByKey.Keys) {
        if (-not $previousByKey.ContainsKey($key)) {
            $added += [pscustomobject]@{
                Identity = $key
                Current  = $currentByKey[$key]
            }

            continue
        }

        $previousItem = $previousByKey[$key]
        $currentItem = $currentByKey[$key]

        $propertyNames = @(
            $previousItem.PSObject.Properties.Name +
            $currentItem.PSObject.Properties.Name |
            Sort-Object -Unique
        )

        foreach ($propertyName in $propertyNames) {
            if ($propertyName -eq $IdentityProperty) {
                continue
            }

            $previousValue = $previousItem.$propertyName
            $currentValue = $currentItem.$propertyName

            $previousJson = $previousValue |
                ConvertTo-Json -Compress -Depth 5

            $currentJson = $currentValue |
                ConvertTo-Json -Compress -Depth 5

            if ($previousJson -ne $currentJson) {
                $modified += [pscustomobject]@{
                    Identity = $key
                    Property = $propertyName
                    Previous = $previousValue
                    Current  = $currentValue
                }
            }
        }
    }

    foreach ($key in $previousByKey.Keys) {
        if (-not $currentByKey.ContainsKey($key)) {
            $removed += [pscustomobject]@{
                Identity = $key
                Previous = $previousByKey[$key]
            }
        }
    }

    return [pscustomobject]@{
        IdentityProperty = $IdentityProperty
        Added            = $added
        Removed          = $removed
        Modified         = $modified
        HasChanges       = (
            $added.Count -gt 0 -or
            $removed.Count -gt 0 -or
            $modified.Count -gt 0
        )
    }
}

Export-ModuleMember -Function Compare-PowerSentryXState