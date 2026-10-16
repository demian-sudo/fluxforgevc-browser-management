[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$validator = Join-Path $projectRoot 'src\Invoke-FluxForgePolicyValidation.ps1'
$examplePolicy = Join-Path $projectRoot 'config\examples\policies.json'
$schema = Join-Path $projectRoot 'config\schema\policy.schema.json'
$capabilities = Join-Path $projectRoot 'config\provider-capabilities.json'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "FluxForgeVC-PolicyTest-$([guid]::NewGuid().ToString('N'))"
$script:testCount = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
    $script:testCount++
}

function Write-TestJson {
    param([string]$Path, [object]$Value)
    [System.IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100), [System.Text.UTF8Encoding]::new($false))
}

function Invoke-TestValidation {
    param(
        [object]$Document,
        [string]$Name,
        [string]$CapabilityRegistryPath = $capabilities
    )
    $caseDirectory = Join-Path $testRoot $Name
    $null = New-Item -ItemType Directory -Path $caseDirectory -Force
    $policyPath = Join-Path $caseDirectory 'policies.json'
    Write-TestJson -Path $policyPath -Value $Document
    $outputDirectory = Join-Path $caseDirectory 'reports'
    $processResult = Invoke-ValidatorProcess -PolicyPath $policyPath -OutputDirectory $outputDirectory -CapabilityRegistryPath $CapabilityRegistryPath
    if (-not $processResult.Report) {
        throw "Validator did not emit a report for test case '$Name'. $($processResult.StandardError)"
    }
    $processResult.Report | Add-Member -NotePropertyName processExitCode -NotePropertyValue $processResult.ExitCode
    $processResult.Report | Add-Member -NotePropertyName jsonReportPath -NotePropertyValue $processResult.JsonReportPath
    $processResult.Report | Add-Member -NotePropertyName markdownReportPath -NotePropertyValue $processResult.MarkdownReportPath
    $processResult.Report
}

function Invoke-ValidatorProcess {
    param(
        [string]$PolicyPath,
        [string]$OutputDirectory,
        [string]$Mode = 'audit',
        [string]$CapabilityRegistryPath = $capabilities
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new((Get-Command pwsh -ErrorAction Stop).Source)
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
        '-NoProfile',
        '-File', $validator,
        '-PolicyPath', $PolicyPath,
        '-CapabilityRegistryPath', $CapabilityRegistryPath,
        '-OutputDirectory', $OutputDirectory,
        '-Mode', $Mode
    )) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()

    $jsonReport = Get-ChildItem -LiteralPath $OutputDirectory -Filter 'Policy-Audit-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    $markdownReport = Get-ChildItem -LiteralPath $OutputDirectory -Filter 'Policy-Audit-*.md' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    [pscustomobject]@{
        ExitCode = $exitCode
        StandardOutput = $stdout
        StandardError = $stderr
        JsonReportPath = if ($jsonReport) { $jsonReport.FullName } else { $null }
        MarkdownReportPath = if ($markdownReport) { $markdownReport.FullName } else { $null }
        Report = if ($jsonReport) { Get-Content -LiteralPath $jsonReport.FullName -Raw | ConvertFrom-Json } else { $null }
    }
}

function Copy-TestPolicy {
    param([object]$Document)
    return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Document -Depth 100) -AsHashtable -Depth 100
}

try {
    $null = New-Item -ItemType Directory -Path $testRoot -Force

    $examples = & $validator -OutputDirectory (Join-Path $testRoot 'examples')
    Assert-True ($examples.isValid -and $examples.summary.policyCount -eq 7) 'Seven example policies should pass structural validation.'
    Assert-True (-not $examples.providerContacted -and -not $examples.changesMade -and $examples.dryRun) 'Validation must remain offline, read-only, and dry-run.'
    Assert-True ((Test-Path -LiteralPath $examples.jsonReportPath) -and (Test-Path -LiteralPath $examples.markdownReportPath)) 'Both report formats must be generated.'
    Assert-True (($examples.policies | Where-Object { $_.observedState -ne 'NOT_VERIFIED' }).Count -eq 0) 'Offline validation must not claim observed provider state.'
    Assert-True (($examples.findings | Where-Object { $_.status -eq 'NOT_VERIFIED' }).Count -gt 0) 'Unknown capabilities must remain explicitly unverified.'
    $validProcess = Invoke-ValidatorProcess -PolicyPath $examplePolicy -OutputDirectory (Join-Path $testRoot 'valid-process')
    Assert-True ($validProcess.ExitCode -eq 0 -and $validProcess.Report.isValid) 'Valid policies must exit successfully as a command-line process.'

    $validDocument = Get-Content -LiteralPath $examplePolicy -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    $badValue = Copy-TestPolicy $validDocument
    $badValue.policies[0].severity = 'urgent'
    $badValueDirectory = Join-Path $testRoot 'invalid-enum'
    $badValueResult = Invoke-TestValidation $badValue 'invalid-enum'
    Assert-True (-not $badValueResult.isValid -and $badValueResult.validationExitCode -eq 1) 'Invalid schema values must fail validation.'
    Assert-True ($badValueResult.processExitCode -ne 0 -and -not $badValueResult.isValid) 'Schema-invalid policies must return a nonzero process exit code and retain their report.'

    $missingField = Copy-TestPolicy $validDocument
    $missingField.policies[0].Remove('securityObjective')
    $missingFieldResult = Invoke-TestValidation $missingField 'missing-required-field'
    Assert-True (-not $missingFieldResult.isValid) 'Missing required policy fields must be rejected.'

    $unexpectedField = Copy-TestPolicy $validDocument
    $unexpectedField.policies[0]['unexpectedField'] = 'unexpected'
    $unexpectedFieldResult = Invoke-TestValidation $unexpectedField 'unexpected-field'
    Assert-True (-not $unexpectedFieldResult.isValid) 'Unexpected policy fields must be rejected.'

    $emptyResult = Invoke-TestValidation @{ schemaVersion = '1.0'; policies = @() } 'empty-policies'
    Assert-True (-not $emptyResult.isValid) 'An empty policy set must fail validation.'

    $duplicate = Copy-TestPolicy $validDocument
    $duplicate.policies[1].policyId = $duplicate.policies[0].policyId
    $duplicateResult = Invoke-TestValidation $duplicate 'duplicate-id'
    Assert-True (-not $duplicateResult.isValid -and ($duplicateResult.findings | Where-Object { $_.message -eq 'Duplicate policy ID.' }).Count -eq 1) 'Duplicate policy IDs must be rejected.'

    $missingDependency = Copy-TestPolicy $validDocument
    $missingDependency.policies[0].dependencies = @('POLICY-DOES-NOT-EXIST')
    $missingDependencyResult = Invoke-TestValidation $missingDependency 'missing-dependency'
    Assert-True (($missingDependencyResult.findings | Where-Object { $_.message -eq 'A declared policy dependency is missing.' }).Count -eq 1) 'Missing dependencies must be detected.'

    $declaredConflict = Copy-TestPolicy $validDocument
    $declaredConflict.policies[0].conflicts = @([string]$declaredConflict.policies[1].policyId)
    $declaredConflictResult = Invoke-TestValidation $declaredConflict 'declared-conflict'
    Assert-True (($declaredConflictResult.findings | Where-Object { $_.message -eq 'A declared conflicting policy is present in the document.' }).Count -eq 1) 'Declared policy conflicts must be detected.'

    $settingConflict = Copy-TestPolicy $validDocument
    $settingConflict.policies += (Copy-TestPolicy @{ policies = @($settingConflict.policies[0]) }).policies[0]
    $settingConflict.policies[-1].policyId = 'CONFIDENTIALSENTINEL-SETTING-CONFLICT'
    $settingConflict.policies[-1].settings.hostFirewall['enabled'] = $false
    $settingConflictResult = Invoke-TestValidation $settingConflict 'setting-conflict'
    Assert-True (($settingConflictResult.findings | Where-Object { $_.message -eq 'Policies specify conflicting values for the same setting path.' }).Count -gt 0) 'Conflicting settings must be detected.'
    $conflictJson = Get-Content -LiteralPath $settingConflictResult.jsonReportPath -Raw
    $conflictMarkdown = Get-Content -LiteralPath $settingConflictResult.markdownReportPath -Raw
    Assert-True (-not $conflictJson.Contains('CONFIDENTIALSENTINEL-SETTING-CONFLICT') -and -not $conflictMarkdown.Contains('CONFIDENTIALSENTINEL-SETTING-CONFLICT')) 'Conflict findings must not disclose user-supplied policy IDs.'

    $missingPrerequisite = & $validator -PolicyPath $examplePolicy -SchemaPath $schema -CapabilityRegistryPath $capabilities -OutputDirectory (Join-Path $testRoot 'missing-prerequisite')
    Assert-True (($missingPrerequisite.findings | Where-Object { $_.status -eq 'NOT_CONFIGURED' }).Count -gt 0) 'Unconfirmed prerequisites must be reported.'

    $unsupportedRegistry = Get-Content -LiteralPath $capabilities -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    $unsupportedRegistry.providers.windows.capabilities = @{
        'managed-host-firewall-policy' = @{ status = 'unsupported'; evidence = 'Test fixture only.' }
    }
    $unsupportedPath = Join-Path $testRoot 'unsupported-registry.json'
    Write-TestJson $unsupportedPath $unsupportedRegistry
    $unsupportedResult = Invoke-TestValidation $validDocument 'unsupported-capability' -CapabilityRegistryPath $unsupportedPath
    Assert-True (($unsupportedResult.findings | Where-Object { $_.status -eq 'UNSUPPORTED' }).Count -gt 0) 'Explicitly unsupported capabilities must be distinct.'

    $supportedRegistry = Get-Content -LiteralPath $capabilities -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    $supportedRegistry.providers.windows.capabilities = @{
        'managed-host-firewall-policy' = @{ status = 'supported'; evidence = 'Test fixture only.' }
    }
    $supportedPath = Join-Path $testRoot 'supported-registry.json'
    Write-TestJson $supportedPath $supportedRegistry
    $supportedResult = & $validator -PolicyPath $examplePolicy -SchemaPath $schema -CapabilityRegistryPath $supportedPath -OutputDirectory (Join-Path $testRoot 'supported')
    Assert-True (($supportedResult.findings | Where-Object { $_.status -eq 'PASS' }).Count -gt 0) 'Static supported capability entries must produce a PASS distinct from observed enforcement.'

    $missingRollback = Copy-TestPolicy $validDocument
    $missingRollback.policies[0].enforcementMode = 'enforce'
    $missingRollback.policies[0].Remove('rollback')
    $missingRollbackResult = Invoke-TestValidation $missingRollback 'missing-rollback'
    Assert-True (-not $missingRollbackResult.isValid) 'Enforcement proposals must require schema rollback information.'

    foreach ($unsafeProperty in 'required', 'destructiveConfirmationRequired') {
        $unsafeRollback = Copy-TestPolicy $validDocument
        $unsafeRollback.policies[0].enforcementMode = 'enforce'
        $unsafeRollback.policies[0].rollback[$unsafeProperty] = $false
        $unsafeRollbackResult = Invoke-TestValidation $unsafeRollback "unsafe-rollback-$unsafeProperty"
        Assert-True (-not $unsafeRollbackResult.isValid) "Enforcement schema must reject rollback.$unsafeProperty=false."
    }

    $blankRollback = Copy-TestPolicy $validDocument
    $blankRollback.policies[0].enforcementMode = 'enforce'
    $blankRollback.policies[0].rollback.plan = '   '
    $blankRollbackResult = Invoke-TestValidation $blankRollback 'blank-rollback-plan'
    Assert-True (-not $blankRollbackResult.isValid) 'Enforcement schema must reject a whitespace-only rollback plan.'

    foreach ($invalidDate in @('not-a-date', '2027-99-99', '2027-02-29', '2027/10/16', '2027-2-01')) {
        $dateDocument = Copy-TestPolicy $validDocument
        $dateDocument.policies[0].reviewDate = $invalidDate
        $dateDirectory = "invalid-date-$([array]::IndexOf(@('not-a-date', '2027-99-99', '2027-02-29', '2027/10/16', '2027-2-01'), $invalidDate))"
        $dateFile = Join-Path $testRoot "$dateDirectory.json"
        Write-TestJson $dateFile $dateDocument
        $dateProcess = Invoke-ValidatorProcess -PolicyPath $dateFile -OutputDirectory (Join-Path $testRoot "$dateDirectory-report")
        Assert-True ($dateProcess.ExitCode -ne 0 -and -not $dateProcess.Report.isValid) "Invalid review date '$invalidDate' must be rejected with a nonzero process exit code."
    }

    $validLeapDate = Copy-TestPolicy $validDocument
    $validLeapDate.policies[0].reviewDate = '2028-02-29'
    $validLeapPath = Join-Path $testRoot 'valid-leap-date.json'
    Write-TestJson $validLeapPath $validLeapDate
    $validLeapProcess = Invoke-ValidatorProcess -PolicyPath $validLeapPath -OutputDirectory (Join-Path $testRoot 'valid-leap-date-report')
    Assert-True ($validLeapProcess.ExitCode -eq 0 -and $validLeapProcess.Report.isValid) 'A real leap-day review date must be accepted.'

    $secret = 'CONFIDENTIALSENTINEL-6D746B87-DO-NOT-DISCLOSE'
    $secretDocument = Copy-TestPolicy $validDocument
    $secretDocument.policies[0].policyId = 'CONFIDENTIALSENTINEL-6D746B87'
    $secretDocument.policies[0].platform = $secret
    $secretDocument.policies[0].owner = $secret
    $secretDocument.policies[0].settings['clientSecret'] = $secret
    $secretDocument.policies[0].prerequisites = @($secret)
    $secretDocument.policies[0].capabilityRequirements = @($secret)
    $secretResult = Invoke-TestValidation $secretDocument 'secret-redaction'
    $jsonText = Get-Content -LiteralPath $secretResult.jsonReportPath -Raw
    $markdownText = Get-Content -LiteralPath $secretResult.markdownReportPath -Raw
    Assert-True (-not $jsonText.Contains($secret) -and -not $markdownText.Contains($secret)) 'Reports must not include settings or secret values.'
    Assert-True (-not $jsonText.Contains('CONFIDENTIALSENTINEL-6D746B87') -and -not $markdownText.Contains('CONFIDENTIALSENTINEL-6D746B87')) 'Reports must not include free-text platform, owner, or user-chosen policy IDs.'
    Assert-True ($markdownText.Contains('confidence:') -and $markdownText.Contains('verification:')) 'Markdown findings must include confidence and verification status.'

    $before = @(Get-ChildItem -LiteralPath $testRoot -Recurse -File).Count
    $enforceBlocked = $false
    try {
        & $validator -Mode enforce -OutputDirectory (Join-Path $testRoot 'blocked-enforce') | Out-Null
    }
    catch {
        $enforceBlocked = $_.Exception.Message -match 'not implemented'
    }
    $after = @(Get-ChildItem -LiteralPath $testRoot -Recurse -File).Count
    Assert-True ($enforceBlocked -and $before -eq $after) 'Enforcement mode must be blocked before report creation.'

    $badJsonPath = Join-Path $testRoot 'malformed.json'
    [System.IO.File]::WriteAllText($badJsonPath, '{"policies": [}', [System.Text.UTF8Encoding]::new($false))
    $malformedProcess = Invoke-ValidatorProcess -PolicyPath $badJsonPath -OutputDirectory (Join-Path $testRoot 'malformed-report')
    Assert-True ($malformedProcess.ExitCode -ne 0 -and -not $malformedProcess.Report.isValid -and $malformedProcess.Report.summary.errorCount -gt 0) 'Malformed JSON must yield a report and nonzero process exit code.'
    Assert-True ($malformedProcess.JsonReportPath -and $malformedProcess.MarkdownReportPath) 'Malformed input must retain JSON and Markdown reports when report writing is possible.'

    $gitCommand = Get-Command git -ErrorAction Stop
    foreach ($ignoredPath in @(
        'id_rsa',
        'id_ed25519',
        'secret.json',
        'app.credentials.json',
        'session_token.txt',
        'local.settings.json',
        'config/local.production.json',
        'reports/policy-audit/report.json'
    )) {
        & $gitCommand.Source -C $projectRoot check-ignore --no-index --quiet -- $ignoredPath
        Assert-True ($LASTEXITCODE -eq 0) "Sensitive path '$ignoredPath' must be ignored by Git."
    }
    foreach ($sourcePath in @('config/examples/policies.json', 'src/SecretManager.ps1', 'src/AccessTokenPolicy.ps1')) {
        & $gitCommand.Source -C $projectRoot check-ignore --no-index --quiet -- $sourcePath
        Assert-True ($LASTEXITCODE -ne 0) "Ordinary example/source path '$sourcePath' must not be ignored."
    }

    $workflowPath = Join-Path $projectRoot '.github\workflows\offline-validation.yml'
    $workflowText = Get-Content -LiteralPath $workflowPath -Raw
    Assert-True ($workflowText.Contains('persist-credentials: false')) 'Checkout credentials must not persist in CI.'
    Assert-True ($workflowText.Contains('permissions:') -and $workflowText.Contains('contents: read')) 'CI permissions must remain explicitly read-only.'
    Assert-True ($workflowText -match 'actions/checkout@[0-9a-f]{40}') 'Checkout action must use an immutable commit pin.'
    $readmeText = Get-Content -LiteralPath (Join-Path $projectRoot 'README.md') -Raw
    Assert-True ($readmeText.Contains('runtime included in `ubuntu-latest`') -and -not $readmeText.Contains('PowerShell setup action')) 'README must describe the runner-provided PowerShell runtime accurately.'

    # Expected nonzero git check-ignore results must not become the test process exit code.
    $global:LASTEXITCODE = 0
    Write-Host "PASS: $script:testCount offline policy assertions passed."
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
