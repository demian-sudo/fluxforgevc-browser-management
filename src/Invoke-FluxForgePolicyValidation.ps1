[CmdletBinding()]
param(
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\config\examples\policies.json'),
    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\config\schema\policy.schema.json'),
    [string]$CapabilityRegistryPath = (Join-Path $PSScriptRoot '..\config\provider-capabilities.json'),
    [string[]]$AvailablePrerequisite = @(),
    [ValidateSet('inventory', 'audit', 'plan', 'pilot', 'enforce', 'rollback')]
    [string]$Mode = 'audit',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\reports\policy-audit')
)

$ErrorActionPreference = 'Stop'

if ($Mode -in @('pilot', 'enforce', 'rollback')) {
    throw "Mode '$Mode' is not implemented. No provider was contacted and no changes were made."
}

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
            if ([string]$otherPolicy.policyId -le $policyId -or
                [string]$otherPolicy.provider -ne [string]$policy.provider -or
                [string]$otherPolicy.platform -ne [string]$policy.platform) {
                continue
            }
            $otherLeaves = @(Get-SettingLeaves -Value $otherPolicy.settings)
            foreach ($leaf in $settingLeaves) {
                $otherLeaf = $otherLeaves | Where-Object { $_.Path -eq $leaf.Path } | Select-Object -First 1
                if ($otherLeaf -and $otherLeaf.Value -ne $leaf.Value) {
                    Add-PolicyFinding -Status ERROR -PolicyId $policyId -Message 'Policies specify conflicting values for the same setting path.' -Evidence 'Two policies for the same provider and platform declare different values at a shared setting path.' -Confidence high -RecommendedNextAction 'Resolve the setting conflict before planning deployment.'
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
    schemaVersion = '1.0'
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

$report | Add-Member -NotePropertyName jsonReportPath -NotePropertyValue $jsonPath
$report | Add-Member -NotePropertyName markdownReportPath -NotePropertyValue $markdownPath
$report

if (-not $report.isValid) {
    exit 1
}
