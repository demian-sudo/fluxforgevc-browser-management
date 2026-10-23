[CmdletBinding()]
param(
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\config\examples\policies.json'),
    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\config\schema\policy.schema.json'),
    [string]$CapabilityRegistryPath = (Join-Path $PSScriptRoot '..\config\provider-capabilities.json'),
    [string[]]$AvailablePrerequisite = @(),
    [ValidateSet('inventory', 'audit', 'plan', 'pilot', 'enforce', 'rollback')]
    [string]$Mode = 'audit',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\reports\policy-audit'),
    [string]$AuditLogPath
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $AuditLogPath = Join-Path $OutputDirectory 'audit-events.jsonl'
}

function Write-AuditEvent {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('validation_started', 'validation_completed', 'authorization_decision', 'deployment_attempt')]
        [string]$EventType,
        [Parameter(Mandatory)]
        [string]$Outcome,
        [string]$Reason,
        [object]$IsValid,
        [object]$ErrorCount
    )

    $auditDirectory = Split-Path -Parent $AuditLogPath
    if ($auditDirectory) {
        $null = New-Item -ItemType Directory -Path $auditDirectory -Force
    }

    $record = [ordered]@{
        timestamp = [datetime]::UtcNow.ToString('o')
        eventType = $EventType
        mode = $Mode
        outcome = $Outcome
        reason = $Reason
        isValid = $IsValid
        errorCount = $ErrorCount
        providerContacted = $false
        changesMade = $false
    }
    $line = ConvertTo-Json -InputObject $record -Compress -Depth 10
    [System.IO.File]::AppendAllText($AuditLogPath, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

if ($Mode -in @('pilot', 'enforce', 'rollback')) {
    Write-AuditEvent -EventType authorization_decision -Outcome denied -Reason 'Authorization is not implemented for this mode.'
    Write-AuditEvent -EventType deployment_attempt -Outcome blocked -Reason 'Provider operations are not implemented; no changes were made.'
    throw "Mode '$Mode' is not implemented. No provider was contacted and no changes were made."
}

Write-AuditEvent -EventType validation_started -Outcome started

$generatedAt = [datetime]::UtcNow.ToString('o')
$findings = [System.Collections.Generic.List[object]]::new()
$policyResults = [System.Collections.Generic.List[object]]::new()
$policyDocument = $null
$capabilityRegistry = $null
$schemaValid = $false
$safePolicyReferences = @{}

function Add-PolicyFinding {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'FAIL', 'WARNING', 'NOT_CONFIGURED', 'UNSUPPORTED', 'NOT_VERIFIED', 'ERROR')]
        [string]$Status,
        [Parameter(Mandatory)]
        [string]$PolicyId,
        [Parameter(Mandatory)]
        [string]$Message,
        [Parameter(Mandatory)]
        [string]$Evidence,
        [Parameter(Mandatory)]
        [ValidateSet('high', 'medium', 'low', 'not-applicable')]
        [string]$Confidence,
        [Parameter(Mandatory)]
        [string]$RecommendedNextAction,
        [string]$Source = 'OfflinePolicyValidator'
    )

    $policyReference = if ($safePolicyReferences.ContainsKey($PolicyId)) {
        $safePolicyReferences[$PolicyId]
    }
    elseif ($PolicyId -in @('DOCUMENT', 'SCHEMA', 'CAPABILITIES')) {
        $PolicyId
    }
    else {
        'DOCUMENT'
    }

    $findings.Add([pscustomobject][ordered]@{
        status = $Status
        policyRef = $policyReference
        message = $Message
        source = $Source
        timestamp = $generatedAt
        evidence = $Evidence
        confidence = $Confidence
        verificationStatus = if ($Status -eq 'NOT_VERIFIED') { 'not-verified' } elseif ($Status -eq 'UNSUPPORTED') { 'unsupported' } elseif ($Status -eq 'NOT_CONFIGURED') { 'not-configured' } else { 'offline-validation-only' }
        recommendedNextAction = $RecommendedNextAction
    })
}

function Get-CapabilityStatus {
    param(
        [Parameter(Mandatory)]
        [string]$Provider,
        [Parameter(Mandatory)]
        [string]$Capability
    )

    if (-not $capabilityRegistry -or
        -not $capabilityRegistry.providers -or
        -not $capabilityRegistry.providers.Contains($Provider)) {
        return 'unknown'
    }

    $providerEntry = $capabilityRegistry.providers[$Provider]
    if (-not $providerEntry.capabilities -or -not $providerEntry.capabilities.Contains($Capability)) {
        return 'unknown'
    }

    $status = [string]$providerEntry.capabilities[$Capability].status
    if ($status -notin @('supported', 'unsupported', 'unknown')) {
        return 'unknown'
    }
    return $status
}

function Get-SettingLeaves {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Value,
        [string]$Prefix = ''
    )

    foreach ($key in $Value.Keys) {
        $path = if ($Prefix) { "$Prefix.$key" } else { [string]$key }
        $child = $Value[$key]
        if ($child -is [System.Collections.IDictionary] -and $child.Count -gt 0) {
            Get-SettingLeaves -Value $child -Prefix $path
        }
        else {
            [pscustomobject]@{
                Path = $path
                Value = ConvertTo-Json -InputObject $child -Compress -Depth 100
            }
        }
    }
}

function Get-GroupLineage {
    param(
        [Parameter(Mandatory)]
        [string]$GroupId,
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Groups
    )

    $lineage = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($GroupId)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        if (-not $lineage.Add($current) -or -not $Groups.Contains($current)) {
            continue
        }
        foreach ($parent in @($Groups[$current].parentGroupIds)) {
            $pending.Push([string]$parent)
        }
    }
    return $lineage
}

function Test-GroupExcludesScope {
    param(
        [string[]]$ExcludedGroupIds,
        [string]$ScopeGroupId,
        [System.Collections.IDictionary]$Groups
    )

    foreach ($excludedGroupId in $ExcludedGroupIds) {
        if (-not $Groups.Contains($excludedGroupId)) {
            continue
        }
        if ((Get-GroupLineage -GroupId $ScopeGroupId -Groups $Groups).Contains($excludedGroupId)) {
            return $true
        }
    }
    return $false
}

function Get-TargetScopeRelation {
    param(
        [Parameter(Mandatory)]
        [object]$LeftPolicy,
        [Parameter(Mandatory)]
        [object]$RightPolicy,
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Groups
    )

    $leftTarget = $LeftPolicy.target
    $rightTarget = $RightPolicy.target
    if ($leftTarget.kind -ne $rightTarget.kind) {
        return 'disjoint'
    }
    if ($leftTarget.kind -eq 'provider') {
        if ([string]$LeftPolicy.provider -eq [string]$RightPolicy.provider) {
            if ([string]$leftTarget.providerScope -eq [string]$rightTarget.providerScope) {
                return 'overlap'
            }
            return 'ambiguous'
        }
        return 'disjoint'
    }

    $sharedTypes = @($leftTarget.deviceTypes | Where-Object { $_ -in @($rightTarget.deviceTypes) })
    $sharedOperatingSystems = @($leftTarget.operatingSystems | Where-Object { $_ -in @($rightTarget.operatingSystems) })
    $ambiguous = $false
    foreach ($deviceId in @($leftTarget.deviceIds)) {
        if ($deviceId -in @($rightTarget.deviceIds) -and
            $deviceId -notin @($leftTarget.excludedDeviceIds) -and
            $deviceId -notin @($rightTarget.excludedDeviceIds)) {
            if ($sharedTypes.Count -eq 0 -or $sharedOperatingSystems.Count -eq 0) {
                return 'ambiguous'
            }
            return 'overlap'
        }
    }
    if ($sharedTypes.Count -eq 0 -or $sharedOperatingSystems.Count -eq 0) {
        return 'disjoint'
    }

    foreach ($leftGroupId in @($leftTarget.groupIds)) {
        if (-not $Groups.Contains($leftGroupId)) {
            continue
        }
        $leftGroup = $Groups[$leftGroupId]
        if ($leftGroup.deviceType -notin $sharedTypes -or
            @($leftGroup.operatingSystems | Where-Object { $_ -in $sharedOperatingSystems }).Count -eq 0) {
            continue
        }
        foreach ($rightGroupId in @($rightTarget.groupIds)) {
            if (-not $Groups.Contains($rightGroupId)) {
                continue
            }
            $rightGroup = $Groups[$rightGroupId]
            if ($rightGroup.deviceType -notin $sharedTypes -or
                @($rightGroup.operatingSystems | Where-Object { $_ -in $sharedOperatingSystems }).Count -eq 0) {
                continue
            }

            $leftLineage = Get-GroupLineage -GroupId $leftGroupId -Groups $Groups
            $rightLineage = Get-GroupLineage -GroupId $rightGroupId -Groups $Groups
            if ((Test-GroupExcludesScope -ExcludedGroupIds @($leftTarget.excludedGroupIds) -ScopeGroupId $rightGroupId -Groups $Groups) -or
                (Test-GroupExcludesScope -ExcludedGroupIds @($rightTarget.excludedGroupIds) -ScopeGroupId $leftGroupId -Groups $Groups)) {
                continue
            }
            $relatedGroupId = if ($leftLineage.Contains($rightGroupId)) { $rightGroupId }
                elseif ($rightLineage.Contains($leftGroupId)) { $leftGroupId }
                else { $null }
            if ($relatedGroupId) {
                if ((Test-GroupExcludesScope -ExcludedGroupIds @($leftTarget.excludedGroupIds) -ScopeGroupId $relatedGroupId -Groups $Groups) -or
                    (Test-GroupExcludesScope -ExcludedGroupIds @($rightTarget.excludedGroupIds) -ScopeGroupId $relatedGroupId -Groups $Groups)) {
                    continue
                }
                return 'overlap'
            }
            $ambiguous = $true
        }
    }

    foreach ($deviceId in @($leftTarget.deviceIds)) {
        if ($deviceId -in @($rightTarget.excludedDeviceIds)) {
            continue
        }
        if (@($rightTarget.groupIds).Count -gt 0) {
            $ambiguous = $true
        }
    }
    foreach ($deviceId in @($rightTarget.deviceIds)) {
        if ($deviceId -in @($leftTarget.excludedDeviceIds)) {
            continue
        }
        if (@($leftTarget.groupIds).Count -gt 0) {
            $ambiguous = $true
        }
    }

    if ($ambiguous) { return 'ambiguous' }
    return 'disjoint'
}

function Get-CyclicPolicyIds {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$PolicyIds
    )

    $orderedPolicyIds = [string[]]@($PolicyIds.Keys)
    [Array]::Sort($orderedPolicyIds, [System.StringComparer]::Ordinal)
    $adjacency = @{}
    $reverseAdjacency = @{}
    foreach ($policyId in $orderedPolicyIds) {
        $adjacency[$policyId] = [System.Collections.Generic.List[string]]::new()
        $reverseAdjacency[$policyId] = [System.Collections.Generic.List[string]]::new()
    }

    foreach ($policyId in $orderedPolicyIds) {
        foreach ($dependency in @($PolicyIds[$policyId].dependencies)) {
            $dependencyId = [string]$dependency
            if ($PolicyIds.Contains($dependencyId) -and $dependencyId -ne $policyId) {
                $adjacency[$policyId].Add($dependencyId)
                $reverseAdjacency[$dependencyId].Add($policyId)
            }
        }
    }
    foreach ($policyId in $orderedPolicyIds) {
        $adjacency[$policyId].Sort([System.StringComparer]::Ordinal)
        $reverseAdjacency[$policyId].Sort([System.StringComparer]::Ordinal)
    }

    # Iterative Kosaraju traversal avoids recursive calls while identifying every cyclic SCC.
    $visited = @{}
    $finishOrder = [System.Collections.Generic.List[string]]::new()
    foreach ($rootPolicyId in $orderedPolicyIds) {
        if ($visited.ContainsKey($rootPolicyId)) {
            continue
        }

        $visited[$rootPolicyId] = $true
        $frames = [System.Collections.Generic.Stack[object]]::new()
        $frames.Push([pscustomobject]@{ PolicyId = $rootPolicyId; NextNeighbor = 0 })
        while ($frames.Count -gt 0) {
            $frame = $frames.Peek()
            $neighbors = $adjacency[$frame.PolicyId]
            if ($frame.NextNeighbor -lt $neighbors.Count) {
                $neighbor = $neighbors[$frame.NextNeighbor]
                $frame.NextNeighbor++
                if (-not $visited.ContainsKey($neighbor)) {
                    $visited[$neighbor] = $true
                    $frames.Push([pscustomobject]@{ PolicyId = $neighbor; NextNeighbor = 0 })
                }
            }
            else {
                [void]$frames.Pop()
                $finishOrder.Add($frame.PolicyId)
            }
        }
    }

    $visited = @{}
    $cyclicPolicyIds = @{}
    for ($finishIndex = $finishOrder.Count - 1; $finishIndex -ge 0; $finishIndex--) {
        $rootPolicyId = $finishOrder[$finishIndex]
        if ($visited.ContainsKey($rootPolicyId)) {
            continue
        }

        $component = [System.Collections.Generic.List[string]]::new()
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $visited[$rootPolicyId] = $true
        $pending.Push($rootPolicyId)
        while ($pending.Count -gt 0) {
            $policyId = $pending.Pop()
            $component.Add($policyId)
            foreach ($neighbor in $reverseAdjacency[$policyId]) {
                if (-not $visited.ContainsKey($neighbor)) {
                    $visited[$neighbor] = $true
                    $pending.Push($neighbor)
                }
            }
        }

        if ($component.Count -gt 1) {
            foreach ($policyId in $component) {
                $cyclicPolicyIds[$policyId] = $true
            }
        }
    }

    return $cyclicPolicyIds
}

if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
    Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'Policy document is unavailable.' -Evidence 'The configured local policy file was not found.' -Confidence high -RecommendedNextAction 'Provide a readable local policy document.'
}
elseif (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
    Add-PolicyFinding -Status ERROR -PolicyId 'SCHEMA' -Message 'Policy schema is unavailable.' -Evidence 'The configured local schema file was not found.' -Confidence high -RecommendedNextAction 'Restore the versioned local policy schema.'
}
else {
    try {
        $rawPolicyDocument = Get-Content -LiteralPath $PolicyPath -Raw -ErrorAction Stop
        $policyDocument = ConvertFrom-Json -InputObject $rawPolicyDocument -AsHashtable -Depth 100 -ErrorAction Stop
        $schemaValid = Test-Json -Json $rawPolicyDocument -SchemaFile $SchemaPath -ErrorAction Stop
        if (-not $schemaValid) {
            Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'Policy document does not comply with the policy schema.' -Evidence 'Offline JSON Schema validation failed.' -Confidence high -RecommendedNextAction 'Correct the local schema violations and re-run validation.'
        }
    }
    catch {
        Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'Policy document could not be parsed or schema-validated.' -Evidence 'The local JSON input or schema is invalid; raw parser details are omitted.' -Confidence high -RecommendedNextAction 'Check local JSON syntax and schema, then re-run validation.'
    }
}

if (-not (Test-Path -LiteralPath $CapabilityRegistryPath -PathType Leaf)) {
    Add-PolicyFinding -Status WARNING -PolicyId 'CAPABILITIES' -Message 'Static provider capability registry is unavailable.' -Evidence 'Capability data was not loaded; provider capabilities are treated as unknown.' -Confidence high -RecommendedNextAction 'Restore or provide a reviewed local capability registry.'
}
else {
    try {
        $capabilityRegistry = Get-Content -LiteralPath $CapabilityRegistryPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop
    }
    catch {
        Add-PolicyFinding -Status WARNING -PolicyId 'CAPABILITIES' -Message 'Static provider capability registry is invalid.' -Evidence 'The local registry could not be parsed; provider capabilities are treated as unknown.' -Confidence high -RecommendedNextAction 'Correct the local registry and re-run validation.'
    }
}

if ($schemaValid -and $policyDocument -and $policyDocument.policies) {
    $policyIds = @{}
    $duplicatePolicyIds = @{}
    $policyReferenceCounter = 0
    foreach ($policy in $policyDocument.policies) {
        $policyId = [string]$policy.policyId
        if ($policyIds.ContainsKey($policyId)) {
            $duplicatePolicyIds[$policyId] = $true
            Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Duplicate policy ID.' -Evidence 'The identifier occurs more than once in this document.' -Confidence high -RecommendedNextAction 'Assign each policy a unique policyId.'
        }
        else {
            $policyIds[$policyId] = $policy
            $policyReferenceCounter++
            $safePolicyReferences[$policyId] = 'POLICY-{0:D3}' -f $policyReferenceCounter
        }
    }

    $deviceGroups = @{}
    foreach ($group in @($policyDocument.deviceGroups)) {
        $groupId = [string]$group.groupId
        if ($deviceGroups.ContainsKey($groupId)) {
            Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'Duplicate device group identifier.' -Evidence 'A group identifier occurs more than once in the declared targeting catalog.' -Confidence high -RecommendedNextAction 'Assign each device group a unique identifier.'
            continue
        }
        $deviceGroups[$groupId] = $group

        foreach ($operatingSystem in @($group.operatingSystems)) {
            if (-not ([string]$operatingSystem).StartsWith("$($group.deviceType)-", [System.StringComparison]::Ordinal)) {
                Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'Device group operating-system compatibility is invalid.' -Evidence 'A declared operating system does not match the device type for its group.' -Confidence high -RecommendedNextAction 'Correct the group device type or operating-system list.'
            }
        }
    }

    $cyclicGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($groupId in @($deviceGroups.Keys | Sort-Object -CaseSensitive)) {
        foreach ($parentGroupId in @($deviceGroups[$groupId].parentGroupIds)) {
            if (-not $deviceGroups.ContainsKey([string]$parentGroupId)) {
                Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'A device group parent reference is missing.' -Evidence 'A declared parent group is not present in the local targeting catalog.' -Confidence high -RecommendedNextAction 'Add the referenced group or correct the parentGroupIds entry.'
                continue
            }
            if ((Get-GroupLineage -GroupId ([string]$parentGroupId) -Groups $deviceGroups).Contains($groupId)) {
                [void]$cyclicGroupIds.Add($groupId)
            }
            if ($deviceGroups[$parentGroupId].deviceType -ne $deviceGroups[$groupId].deviceType -or
                @($deviceGroups[$groupId].operatingSystems | Where-Object { $_ -notin @($deviceGroups[$parentGroupId].operatingSystems) }).Count -gt 0) {
                Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'Device group hierarchy has incompatible targeting constraints.' -Evidence 'A child group exceeds its parent group device type or operating-system scope.' -Confidence high -RecommendedNextAction 'Make child group constraints a subset of the parent group constraints.'
            }
        }
    }
    foreach ($groupId in @($cyclicGroupIds | Sort-Object -CaseSensitive)) {
        Add-PolicyFinding -Status ERROR -PolicyId 'DOCUMENT' -Message 'Circular device group hierarchy detected.' -Evidence 'The group participates in a cycle among declared parent-group references.' -Confidence high -RecommendedNextAction 'Break the parent-group cycle before assigning policies.'
    }

    $cyclicPolicyIds = Get-CyclicPolicyIds -PolicyIds $policyIds
    $cycleFindingAdded = @{}
    foreach ($policy in $policyDocument.policies) {
        $policyId = [string]$policy.policyId
        $policyReference = $safePolicyReferences[$policyId]
        $errorCountBefore = @($findings | Where-Object { $_.policyRef -eq $policyReference -and $_.status -eq 'ERROR' }).Count
        $hasUnsupported = $false
        $hasUnknown = $false
        $hasMissingPrerequisite = $false
        $desiredStatus = if ($policy.desiredState.Count -gt 0) { 'specified' } else { 'not-specified' }

        $deviceProvider = [string]$policy.provider -in @('windows', 'microsoft-intune', 'android-enterprise')
        if (($policy.target.kind -eq 'device') -ne $deviceProvider) {
            Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Policy provider and target kind are incompatible.' -Evidence 'The declared provider is not compatible with the selected device or organization targeting model.' -Confidence high -RecommendedNextAction 'Use the provider-compatible target kind and confirm its scope with current product documentation.'
        }

        if ($policy.target.kind -eq 'device') {
            foreach ($operatingSystem in @($policy.target.operatingSystems)) {
                $expectedDeviceType = ([string]$operatingSystem).Split('-')[0]
                if ($expectedDeviceType -notin @($policy.target.deviceTypes)) {
                    Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Target operating system is incompatible with the declared device types.' -Evidence 'The targeting constraints contain an operating system outside the selected device types.' -Confidence high -RecommendedNextAction 'Align deviceTypes and operatingSystems before assigning this policy.'
                }
            }

            $requiredDeviceType = switch ([string]$policy.provider) {
                'windows' { 'windows' }
                'android-enterprise' { 'android' }
                default { $null }
            }
            if ($requiredDeviceType -and @($policy.target.deviceTypes | Where-Object { $_ -ne $requiredDeviceType }).Count -gt 0) {
                Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Policy provider is incompatible with the target device type.' -Evidence 'The provider label and declared device targeting do not match.' -Confidence high -RecommendedNextAction 'Use a compatible provider and device type; verify product support independently.'
            }

            foreach ($groupId in @($policy.target.groupIds) + @($policy.target.excludedGroupIds)) {
                if (-not $deviceGroups.ContainsKey([string]$groupId)) {
                    Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'A referenced device group is missing.' -Evidence 'A target or exclusion group is not declared in the local group catalog.' -Confidence high -RecommendedNextAction 'Declare the group or correct the policy group reference.'
                }
            }
            foreach ($groupId in @($policy.target.groupIds)) {
                if (-not $deviceGroups.ContainsKey([string]$groupId)) {
                    continue
                }
                $group = $deviceGroups[$groupId]
                if ($group.deviceType -notin @($policy.target.deviceTypes) -or
                    @($group.operatingSystems | Where-Object { $_ -in @($policy.target.operatingSystems) }).Count -eq 0) {
                    Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Target group is incompatible with the policy targeting constraints.' -Evidence 'The group device type or operating-system scope falls outside the policy target.' -Confidence high -RecommendedNextAction 'Align the policy target with its declared group scope.'
                }
            }
            if (@($policy.target.groupIds).Count -gt 0) {
                Add-PolicyFinding -Status NOT_VERIFIED -PolicyId $policyId -Message 'Declared device group membership is not provider-verified.' -Evidence 'The local group catalog contains targeting constraints only; no provider membership or enrollment data was retrieved.' -Confidence high -RecommendedNextAction 'Verify group existence, membership, enrollment, and effective assignments through a separately approved read-only provider integration.'
            }
            $groupsAreAmbiguous = $false
            $targetGroups = @($policy.target.groupIds | Where-Object { $deviceGroups.ContainsKey([string]$_) })
            for ($groupIndex = 0; $groupIndex -lt $targetGroups.Count; $groupIndex++) {
                for ($otherGroupIndex = $groupIndex + 1; $otherGroupIndex -lt $targetGroups.Count; $otherGroupIndex++) {
                    $leftGroupId = [string]$targetGroups[$groupIndex]
                    $rightGroupId = [string]$targetGroups[$otherGroupIndex]
                    $leftLineage = Get-GroupLineage -GroupId $leftGroupId -Groups $deviceGroups
                    $rightLineage = Get-GroupLineage -GroupId $rightGroupId -Groups $deviceGroups
                    if (-not $leftLineage.Contains($rightGroupId) -and -not $rightLineage.Contains($leftGroupId) -and
                        $deviceGroups[$leftGroupId].deviceType -eq $deviceGroups[$rightGroupId].deviceType -and
                        @($deviceGroups[$leftGroupId].operatingSystems | Where-Object { $_ -in @($deviceGroups[$rightGroupId].operatingSystems) }).Count -gt 0) {
                        $groupsAreAmbiguous = $true
                    }
                }
            }
            if ($groupsAreAmbiguous) {
                Add-PolicyFinding -Status NOT_VERIFIED -PolicyId $policyId -Message 'Target group overlap is ambiguous.' -Evidence 'Multiple compatible groups have no declared hierarchy or verified membership relationship.' -Confidence high -RecommendedNextAction 'Review provider-side group membership and remove ambiguity before relying on this assignment.'
            }
            $effectiveGroupCount = @($targetGroups | Where-Object {
                -not (Test-GroupExcludesScope -ExcludedGroupIds @($policy.target.excludedGroupIds) -ScopeGroupId ([string]$_) -Groups $deviceGroups)
            }).Count
            $effectiveDeviceCount = @($policy.target.deviceIds | Where-Object { $_ -notin @($policy.target.excludedDeviceIds) }).Count
            if ($effectiveGroupCount -eq 0 -and $effectiveDeviceCount -eq 0) {
                Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Device targeting selects no non-excluded scope.' -Evidence 'All declared group and explicit-device selectors are excluded or unresolved.' -Confidence high -RecommendedNextAction 'Add a valid included target or remove exclusions that eliminate the entire assignment.'
            }
            foreach ($settingRoot in @($policy.settings.Keys)) {
                $settingDeviceType = switch ([string]$settingRoot) {
                    'hostFirewall' { 'windows' }
                    'screenLock' { 'android' }
                    default { $null }
                }
                if ($settingDeviceType -and @($policy.target.deviceTypes | Where-Object { $_ -ne $settingDeviceType }).Count -gt 0) {
                    Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'A known device setting is incompatible with the target device type.' -Evidence 'The setting is defined for a different device family than the policy target.' -Confidence high -RecommendedNextAction 'Align the setting and target device type; verify provider-specific support.'
                }
                elseif (-not $settingDeviceType) {
                    Add-PolicyFinding -Status NOT_VERIFIED -PolicyId $policyId -Message 'Device setting compatibility is not defined by the offline validator.' -Evidence 'No provider-specific setting compatibility catalog is available for this setting.' -Confidence high -RecommendedNextAction 'Verify setting support for every targeted device type and operating-system version before deployment planning.'
                }
            }
            if (@($policy.target.deviceIds).Count -gt 0) {
                Add-PolicyFinding -Status NOT_VERIFIED -PolicyId $policyId -Message 'Explicit device identifiers are syntactically valid but not provider-verified.' -Evidence 'No provider inventory or explicit-device-targeting capability was verified offline.' -Confidence high -RecommendedNextAction 'Do not treat the identifiers as enrolled or targetable until a provider adapter verifies scope.'
            }
        }

        if ($cyclicPolicyIds.ContainsKey($policyId) -and -not $cycleFindingAdded.ContainsKey($policyId)) {
            Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Circular policy dependency detected.' -Evidence 'The policy participates in a cycle among declared policy dependencies.' -Confidence high -RecommendedNextAction 'Break the dependency cycle before planning deployment.'
            $cycleFindingAdded[$policyId] = $true
        }

        $parsedReviewDate = [datetime]::MinValue
        $validReviewDate = [datetime]::TryParseExact(
            [string]$policy.reviewDate,
            'yyyy-MM-dd',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$parsedReviewDate
        )
        if (-not $validReviewDate) {
            Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Policy review date is invalid.' -Evidence 'The review date must be a real calendar date in yyyy-MM-dd format.' -Confidence high -RecommendedNextAction 'Correct the review date and re-run offline validation.'
        }

        foreach ($prerequisite in @($policy.prerequisites)) {
            if ($prerequisite -notin $AvailablePrerequisite) {
                $hasMissingPrerequisite = $true
                Add-PolicyFinding -Status NOT_CONFIGURED -PolicyId $policyId -Message 'A declared prerequisite is not confirmed in the offline context.' -Evidence 'Prerequisite availability was not supplied locally.' -Confidence high -RecommendedNextAction 'Verify each prerequisite independently; supply confirmed local prerequisites only after review.'
            }
        }

        foreach ($dependency in @($policy.dependencies)) {
            if (-not $policyIds.ContainsKey([string]$dependency)) {
                Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'A declared policy dependency is missing.' -Evidence 'A referenced policyId does not exist in this document.' -Confidence high -RecommendedNextAction 'Add the required policy dependency or correct its reference.'
            }
            elseif ([string]$dependency -eq $policyId) {
                Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'A policy cannot depend on itself.' -Evidence 'The dependency reference points to this policy.' -Confidence high -RecommendedNextAction 'Remove the self-referencing dependency.'
            }
        }

        foreach ($conflictId in @($policy.conflicts)) {
            if ($policyIds.ContainsKey([string]$conflictId)) {
                Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'A declared conflicting policy is present in the document.' -Evidence 'Both policies are present in the same policy set.' -Confidence high -RecommendedNextAction 'Resolve declared policy conflicts before planning deployment.'
            }
        }

        foreach ($capability in @($policy.capabilityRequirements)) {
            $capabilityStatus = Get-CapabilityStatus -Provider ([string]$policy.provider) -Capability ([string]$capability)
            switch ($capabilityStatus) {
                'supported' {
                    Add-PolicyFinding -Status PASS -PolicyId $policyId -Message 'A required capability is listed as supported in the static local registry.' -Evidence 'This is static registry evidence only; no live provider capability check was performed.' -Confidence medium -RecommendedNextAction 'Confirm the capability and applicable licensing against current provider documentation before implementation.'
                }
                'unsupported' {
                    $hasUnsupported = $true
                    Add-PolicyFinding -Status UNSUPPORTED -PolicyId $policyId -Message 'A required capability is explicitly marked unsupported in the local registry.' -Evidence 'No live provider capability check was performed.' -Confidence medium -RecommendedNextAction 'Remove or redesign the requirement after verifying current provider support.'
                }
                default {
                    $hasUnknown = $true
                    Add-PolicyFinding -Status NOT_VERIFIED -PolicyId $policyId -Message 'A required provider capability is unknown or not verified.' -Evidence 'The local registry contains no verified support entry; no provider was contacted.' -Confidence high -RecommendedNextAction 'Verify the required capability in current provider documentation and record the evidence.'
                }
            }
        }

        if ($policy.enforcementMode -eq 'enforce' -and
            (-not $policy.rollback -or
                -not $policy.rollback.required -or
                [string]::IsNullOrWhiteSpace([string]$policy.rollback.plan) -or
                -not $policy.rollback.destructiveConfirmationRequired)) {
            Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Enforcement proposal lacks required rollback safeguards.' -Evidence 'Enforcement requires a rollback plan and separate destructive-action confirmation.' -Confidence high -RecommendedNextAction 'Document a viable rollback plan and confirmation requirement; enforcement remains unimplemented.'
        }

        $settingLeaves = @(Get-SettingLeaves -Value $policy.settings)
        foreach ($otherPolicy in $policyDocument.policies) {
            if ([string]::CompareOrdinal([string]$otherPolicy.policyId, $policyId) -le 0 -or
                [string]$otherPolicy.provider -ne [string]$policy.provider) {
                continue
            }
            $scopeRelation = Get-TargetScopeRelation -LeftPolicy $policy -RightPolicy $otherPolicy -Groups $deviceGroups
            if ($scopeRelation -eq 'disjoint') {
                continue
            }
            if ($scopeRelation -eq 'ambiguous') {
                $ambiguityMessage = 'Assignment scope overlap cannot be established offline.'
                $ambiguityEvidence = 'The declared targets are compatible but group membership or provider scope is unavailable.'
                $ambiguityAction = 'Verify the target scopes before relying on assignments or planning deployment.'
                Add-PolicyFinding -Status NOT_VERIFIED -PolicyId $policyId -Message $ambiguityMessage -Evidence $ambiguityEvidence -Confidence high -RecommendedNextAction $ambiguityAction
                Add-PolicyFinding -Status NOT_VERIFIED -PolicyId ([string]$otherPolicy.policyId) -Message $ambiguityMessage -Evidence $ambiguityEvidence -Confidence high -RecommendedNextAction $ambiguityAction
            }
            $otherLeaves = @(Get-SettingLeaves -Value $otherPolicy.settings)
            foreach ($leaf in $settingLeaves) {
                $otherLeaf = $otherLeaves | Where-Object { $_.Path -eq $leaf.Path } | Select-Object -First 1
                if ($otherLeaf -and $otherLeaf.Value -ne $leaf.Value) {
                    if ($scopeRelation -eq 'overlap') {
                        $message = 'Overlapping policy assignments specify contradictory values for the same setting path.'
                        $evidence = 'The target scopes overlap and both policies declare different values at a shared setting path.'
                        $status = 'ERROR'
                        $action = 'Resolve the assignment conflict; no policy is selected as a winner.'
                    }
                    else {
                        $message = 'Potentially overlapping policy assignments have contradictory values.'
                        $evidence = 'The offline declarations cannot establish whether these compatible group scopes overlap.'
                        $status = 'NOT_VERIFIED'
                        $action = 'Verify effective group membership before treating these assignments as disjoint or deploying either policy.'
                    }
                    Add-PolicyFinding -Status $status -PolicyId $policyId -Message $message -Evidence $evidence -Confidence high -RecommendedNextAction $action
                    Add-PolicyFinding -Status $status -PolicyId ([string]$otherPolicy.policyId) -Message $message -Evidence $evidence -Confidence high -RecommendedNextAction $action
                }
            }
        }

        $errorCountAfter = @($findings | Where-Object { $_.policyRef -eq $policyReference -and $_.status -eq 'ERROR' }).Count
        if ($errorCountAfter -gt $errorCountBefore -or $duplicatePolicyIds.ContainsKey($policyId)) {
            $policyStatus = 'ERROR'
        }
        elseif ($hasUnsupported) {
            $policyStatus = 'UNSUPPORTED'
        }
        elseif ($hasMissingPrerequisite) {
            $policyStatus = 'NOT_CONFIGURED'
        }
        else {
            $policyStatus = 'NOT_VERIFIED'
            if (-not $hasUnknown) {
                Add-PolicyFinding -Status NOT_VERIFIED -PolicyId $policyId -Message 'Desired state has no provider or endpoint observation.' -Evidence 'This operation validates local policy data only.' -Confidence high -RecommendedNextAction 'Use a separately approved, supported read-only verification workflow.'
            }
        }

        $policyResults.Add([pscustomobject][ordered]@{
            policyRef = $safePolicyReferences[$policyId]
            provider = [string]$policy.provider
            severity = [string]$policy.severity
            desiredState = $desiredStatus
            desiredStateSummary = if ($desiredStatus -eq 'specified') { 'Configured in document; values omitted.' } else { 'Not specified.' }
            observedState = 'NOT_VERIFIED'
            enforcementMode = [string]$policy.enforcementMode
            status = $policyStatus
            illustrative = [bool]$policy.illustrative
        })
    }
}

$stateCounts = [ordered]@{}
foreach ($state in @('PASS', 'FAIL', 'WARNING', 'NOT_CONFIGURED', 'UNSUPPORTED', 'NOT_VERIFIED', 'ERROR')) {
    $stateCounts[$state] = @($findings | Where-Object status -eq $state).Count
}

$providers = @($policyResults | Select-Object -ExpandProperty provider -Unique)
$report = [pscustomobject][ordered]@{
    schemaVersion = '1.1'
    reportId = "POLICY-AUDIT-$([datetime]::UtcNow.ToString('yyyyMMdd-HHmmssfff'))"
    generatedAt = $generatedAt
    provider = if ($providers.Count -eq 1) { $providers[0] } elseif ($providers.Count -gt 1) { 'multiple' } else { 'unknown' }
    auditMode = $Mode
    source = 'Offline policy validation; no provider was contacted.'
    providerContacted = $false
    changesMade = $false
    dryRun = $true
    isValid = ($stateCounts.ERROR -eq 0)
    validationExitCode = if ($stateCounts.ERROR -eq 0) { 0 } else { 1 }
    summary = [pscustomobject][ordered]@{
        policyCount = $policyResults.Count
        errorCount = $stateCounts.ERROR
        warningCount = ($stateCounts.WARNING + $stateCounts.NOT_CONFIGURED + $stateCounts.UNSUPPORTED + $stateCounts.NOT_VERIFIED)
        stateCounts = [pscustomobject]$stateCounts
    }
    policies = @($policyResults.ToArray())
    findings = @($findings.ToArray())
}

function ConvertTo-MarkdownText {
    param([string]$Value)
    return $Value.Replace('\', '\\').Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ').Replace('`', '\`')
}

$markdown = [System.Collections.Generic.List[string]]::new()
$markdown.Add('# Offline Policy Audit')
$markdown.Add('')
$markdown.Add("- Generated (UTC): $($report.generatedAt)")
$markdown.Add("- Mode: $($report.auditMode)")
$markdown.Add("- Provider scope: $($report.provider)")
$markdown.Add('- Provider contacted: no')
$markdown.Add('- Changes made: no')
$markdown.Add("- Schema and cross-policy validation passed: $($report.isValid)")
$markdown.Add('')
$markdown.Add('## Policy states')
$markdown.Add('')
$markdown.Add('| Policy ID | Provider | Desired state | Observed state | Result |')
$markdown.Add('|---|---|---|---|---|')
foreach ($policyResult in $report.policies) {
    $markdown.Add("| $($policyResult.policyRef) | $($policyResult.provider) | $($policyResult.desiredState) | $($policyResult.observedState) | $($policyResult.status) |")
}
$markdown.Add('')
$markdown.Add('Desired setting values are intentionally omitted. `NOT_VERIFIED` is not a pass or fail; no provider or endpoint observation was made.')
$markdown.Add('')
$markdown.Add('## Findings')
$markdown.Add('')
if ($report.findings.Count -eq 0) {
    $markdown.Add('No schema or cross-policy validation findings.')
}
else {
    foreach ($finding in $report.findings) {
        $message = ConvertTo-MarkdownText $finding.message
        $evidence = ConvertTo-MarkdownText $finding.evidence
        $nextAction = ConvertTo-MarkdownText $finding.recommendedNextAction
        $markdown.Add("- **$($finding.status)** — $($finding.policyRef): $message Source: $($finding.source); timestamp: $($finding.timestamp); confidence: $($finding.confidence); verification: $($finding.verificationStatus). Evidence: $evidence Next: $nextAction")
    }
}

$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$reportBaseName = "Policy-Audit-$([datetime]::UtcNow.ToString('yyyyMMdd-HHmmssfff'))"
$jsonPath = Join-Path $OutputDirectory "$reportBaseName.json"
$markdownPath = Join-Path $OutputDirectory "$reportBaseName.md"
$utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($jsonPath, ($report | ConvertTo-Json -Depth 100), $utf8WithoutBom)
[System.IO.File]::WriteAllText($markdownPath, ($markdown -join [Environment]::NewLine), $utf8WithoutBom)
Write-AuditEvent -EventType validation_completed `
    -Outcome $(if ($report.isValid) { 'valid' } else { 'invalid' }) `
    -Reason 'Offline schema and cross-policy validation completed.' `
    -IsValid $report.isValid `
    -ErrorCount $stateCounts.ERROR

$report | Add-Member -NotePropertyName jsonReportPath -NotePropertyValue $jsonPath
$report | Add-Member -NotePropertyName markdownReportPath -NotePropertyValue $markdownPath
$report

if (-not $report.isValid) {
    exit 1
}
