[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $projectRoot 'scripts/windows/FluxForge.WindowsSecurity.psm1'
$defaultPolicyPath = Join-Path $projectRoot 'config/examples/windows-security-policy.json'
$policySchemaPath = Join-Path $projectRoot 'config/schema/windows-security-policy.schema.json'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "FluxForgeWindowsSecurity-$([guid]::NewGuid().ToString('N'))"
$script:testCount = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
    $script:testCount++
}

try {
    Import-Module $modulePath -Force
    $null = New-Item -ItemType Directory -Path $testRoot -Force
    $policyPath = Join-Path $testRoot 'policy.json'
    Copy-Item -LiteralPath $defaultPolicyPath -Destination $policyPath
    Assert-True (Test-Json -Path $defaultPolicyPath -SchemaFile $policySchemaPath) 'The example policy must validate against the Windows security schema.'

    $state = @{
        profiles = @(
            @{ name = 'Domain'; enabled = $false },
            @{ name = 'Private'; enabled = $true },
            @{ name = 'Public'; enabled = $false }
        )
        firewallReads = 0
    }
    $stateReader = {
        param($name)
        if ($name -eq 'Windows Firewall profiles') {
            $state.firewallReads++
            return @($state.profiles)
        }
        return @{ fixture = $true }
    }.GetNewClosure()
    $environment = { [pscustomobject]@{ isWindows = $true; supported = $true; classification = 'Windows11' } }
    $admin = { $true }
    $setterState = @{ calls = 0; failToApply = $false }
    $setter = {
        param($profiles, $enabled)
        $setterState.calls++
        if ($setterState.failToApply) { return }
        foreach ($profileName in $profiles) {
            $profile = $state.profiles | Where-Object name -eq $profileName | Select-Object -First 1
            if ($profile) { $profile.enabled = [bool]$enabled }
        }
    }.GetNewClosure()

    $beforeAuditCalls = $state.firewallReads
    $auditState = Get-FluxForgeWindowsSecurityState -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider $admin
    Assert-True ($auditState.operatingSystem -eq 'Windows11' -and $state.firewallReads -gt $beforeAuditCalls) 'Audit must inspect injected state on supported Windows.'
    Assert-True ($auditState.administratorStatus -eq 'PASS') 'Audit must report verified administrator state.'
    $unknownAdminState = Get-FluxForgeWindowsSecurityState -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider { throw 'unavailable' }
    Assert-True ($unknownAdminState.administratorStatus -eq 'NOT_VERIFIED') 'Unavailable administrator evidence must remain NOT_VERIFIED.'
    Assert-True ($setterState.calls -eq 0) 'Audit must never change settings.'

    $entryPoint = Join-Path $projectRoot 'scripts/windows/Test-FluxForgeWindowsSecurity.ps1'
    $cliReport = (& $entryPoint -OutputDirectory $testRoot -Json) | ConvertFrom-Json
    Assert-True ($cliReport.mode -eq 'Audit' -and -not $cliReport.changesMade -and (Test-Path -LiteralPath $cliReport.reportPath)) 'The entry point must default to read-only Audit and generate a structured report.'
    Assert-True ($cliReport.supportedWindows -eq $false -and @($cliReport.checks | Where-Object status -ne 'NOT_VERIFIED').Count -eq 0) 'Codespaces audit must describe its unsupported container and not claim Windows state.'

    $plan = Get-FluxForgeWindowsPlan -PolicyPath $policyPath -StateReader $stateReader -EnvironmentProvider $environment
    Assert-True ($plan.mode -eq 'Plan' -and -not $plan.changesMade -and $plan.changes.Count -eq 3) 'Plan must preview every requested firewall profile without changes.'
    Assert-True ($setterState.calls -eq 0) 'Plan must never call the setting writer.'
    Assert-True (($plan.changes | Where-Object { $_.profile -eq 'Domain' }).previousValue -eq $false) 'Plan must expose the captured previous state.'

    $unsupportedPolicy = @{ schemaVersion = '1.0'; settings = @(@{ name = 'Defender.Disable'; value = $true; profiles = @('Domain') }) }
    $unsupportedPolicy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $policyPath
    $unsupportedRejected = $false
    try {
        Get-FluxForgeWindowsPlan -PolicyPath $policyPath -StateReader $stateReader -EnvironmentProvider $environment | Out-Null
    }
    catch {
        $unsupportedRejected = $_.Exception.Message -match 'Only FirewallProfile.Enabled'
    }
    Assert-True $unsupportedRejected 'Unsupported settings must be rejected without calling writers.'
    Assert-True ($setterState.calls -eq 0) 'Unsupported settings must fail safely.'
    $unknownPropertyPolicy = @{ schemaVersion = '1.0'; settings = @(@{ name = 'FirewallProfile.Enabled'; value = $true; profiles = @('Domain'); force = $true }) }
    $unknownPropertyPolicy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $policyPath
    $unknownPropertyRejected = $false
    try {
        Get-FluxForgeWindowsPlan -PolicyPath $policyPath -StateReader $stateReader -EnvironmentProvider $environment | Out-Null
    }
    catch {
        $unknownPropertyRejected = $_.Exception.Message -match 'only name, profiles, and value'
    }
    Assert-True $unknownPropertyRejected 'Malformed policies with unsupported fields must be rejected.'
    $caseMismatchPolicy = @{ schemaVersion = '1.0'; settings = @(@{ name = 'FirewallProfile.Enabled'; value = $true; profiles = @('domain') }) }
    $caseMismatchPolicy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $policyPath
    $caseMismatchRejected = $false
    try {
        Get-FluxForgeWindowsPlan -PolicyPath $policyPath -StateReader $stateReader -EnvironmentProvider $environment | Out-Null
    }
    catch {
        $caseMismatchRejected = $_.Exception.Message -match 'Firewall policy profiles'
    }
    Assert-True $caseMismatchRejected 'Policy target identifiers must match supported profile names exactly.'
    Copy-Item -LiteralPath $defaultPolicyPath -Destination $policyPath -Force

    $auditPath = Join-Path $testRoot 'audit-events.jsonl'
    $backupDirectory = Join-Path $testRoot 'backups'
    $noApprovalRejected = $false
    try {
        Set-FluxForgeWindowsSecurityPolicy -PolicyPath $policyPath -BackupDirectory $backupDirectory -AuditLogPath $auditPath -Confirmation '' -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $setter | Out-Null
    }
    catch {
        $noApprovalRejected = $_.Exception.Message -match 'Apply refused'
    }
    Assert-True $noApprovalRejected 'Apply must require the exact explicit confirmation.'
    Assert-True ($setterState.calls -eq 0 -and -not (Test-Path $backupDirectory)) 'Unapproved Apply must not write settings or create recovery data.'
    Assert-True ((Get-Content -LiteralPath $auditPath -Raw) -match 'apply_denied') 'Rejected authorization decisions must be audited.'

    $staleState = @{
        readCount = 0
        profiles = @(@{ name = 'Domain'; enabled = $false }, @{ name = 'Private'; enabled = $false }, @{ name = 'Public'; enabled = $false })
    }
    $staleReader = {
        param($name)
        if ($name -ne 'Windows Firewall profiles') { return @{ fixture = $true } }
        $staleState.readCount++
        if ($staleState.readCount -eq 2) { $staleState.profiles[0].enabled = $true }
        return @($staleState.profiles)
    }.GetNewClosure()
    $staleWriterState = @{ calls = 0 }
    $staleSetter = { param($profiles, $enabled) $staleWriterState.calls++ }.GetNewClosure()
    $stalePlanRejected = $false
    $staleAuditPath = Join-Path $testRoot 'stale-audit.jsonl'
    try {
        Set-FluxForgeWindowsSecurityPolicy -PolicyPath $policyPath -BackupDirectory (Join-Path $testRoot 'stale-backups') -AuditLogPath $staleAuditPath -Confirmation 'APPLY FirewallProfile.Enabled=true' -StateReader $staleReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $staleSetter | Out-Null
    }
    catch {
        $stalePlanRejected = $_.Exception.Message -match 'state changed after the preview'
    }
    $staleEvents = @(Get-Content -LiteralPath $staleAuditPath | ForEach-Object { ConvertFrom-Json $_ })
    Assert-True ($stalePlanRejected -and $staleWriterState.calls -eq 0) 'A target changed after preview must prevent the setting writer from running.'
    Assert-True (($staleEvents | Where-Object eventType -eq 'apply_failed').changesMade -eq $false) 'Aborted stale plans must not claim a system change.'

    $auditFailureState = @{
        profiles = @(@{ name = 'Domain'; enabled = $false }, @{ name = 'Private'; enabled = $false }, @{ name = 'Public'; enabled = $false })
    }
    $auditFailureReader = { param($name) if ($name -eq 'Windows Firewall profiles') { @($auditFailureState.profiles) } }.GetNewClosure()
    $auditFailureWriterState = @{ calls = 0 }
    $auditFailureSetter = { param($profiles, $enabled) $auditFailureWriterState.calls++ }.GetNewClosure()
    $blockedAuditParent = Join-Path $testRoot 'not-a-directory'
    Set-Content -LiteralPath $blockedAuditParent -Value 'block audit log creation'
    $auditFailureRejected = $false
    try {
        Set-FluxForgeWindowsSecurityPolicy -PolicyPath $policyPath -BackupDirectory (Join-Path $testRoot 'audit-failure-backups') -AuditLogPath (Join-Path $blockedAuditParent 'events.jsonl') -Confirmation 'APPLY FirewallProfile.Enabled=true' -StateReader $auditFailureReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $auditFailureSetter | Out-Null
    }
    catch {
        $auditFailureRejected = $true
    }
    Assert-True ($auditFailureRejected -and $auditFailureWriterState.calls -eq 0) 'Audit-log failure must block changes before the setting writer runs.'

    $noAdminRejected = $false
    try {
        Set-FluxForgeWindowsSecurityPolicy -PolicyPath $policyPath -BackupDirectory $backupDirectory -AuditLogPath $auditPath -Confirmation 'APPLY FirewallProfile.Enabled=true' -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider { $false } -Setter $setter | Out-Null
    }
    catch {
        $noAdminRejected = $_.Exception.Message -match 'administrator privileges'
    }
    Assert-True $noAdminRejected 'Apply must refuse when administrator privileges are unavailable.'
    Assert-True ($setterState.calls -eq 0 -and -not (Test-Path $backupDirectory)) 'Missing administrator privileges must not write or back up state.'

    $apply = Set-FluxForgeWindowsSecurityPolicy -PolicyPath $policyPath -BackupDirectory $backupDirectory -AuditLogPath $auditPath -Confirmation 'APPLY FirewallProfile.Enabled=true' -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $setter
    Assert-True ($apply.status -eq 'PASS' -and $apply.changesMade -and (Test-Path -LiteralPath $apply.backupPath)) 'Approved Apply must capture a backup and verify changes.'
    Assert-True (($state.profiles | Where-Object { -not $_.enabled }).Count -eq 0) 'Approved Apply must only enable requested firewall profiles.'
    $backup = Get-Content -LiteralPath $apply.backupPath -Raw | ConvertFrom-Json
    Assert-True (($backup.payload.profiles | Where-Object name -eq 'Domain').enabled -eq $false) 'Backup must capture previous profile state.'

    $auditText = Get-Content -LiteralPath $auditPath -Raw
    Assert-True ($auditText -match 'apply_started' -and $auditText -match 'apply_completed' -and $auditText -notmatch 'password|token|secret|credential') 'Audit records must describe operation outcomes without secret fields.'

    $restoreConfirmation = "RESTORE $($backup.payload.backupId)"
    $restore = Restore-FluxForgeWindowsSecurityPolicy -BackupPath $apply.backupPath -AuditLogPath $auditPath -Confirmation $restoreConfirmation -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $setter
    Assert-True ($restore.status -eq 'PASS' -and ($state.profiles | Where-Object name -eq 'Domain').enabled -eq $false) 'Restore must reproduce the captured verified prior state.'
    $restoreEvents = @(Get-Content -LiteralPath $auditPath | ForEach-Object { ConvertFrom-Json $_ })
    Assert-True (@($restoreEvents | Where-Object eventType -eq 'restore_started').Count -eq 1) 'Each restore attempt must have exactly one start audit event.'

    $state.profiles | ForEach-Object { $_.enabled = $true }
    $staleRestoreState = @{
        reads = 0
        profiles = $state.profiles
    }
    $staleRestoreReader = {
        param($name)
        if ($name -ne 'Windows Firewall profiles') { return @{ fixture = $true } }
        $staleRestoreState.reads++
        if ($staleRestoreState.reads -eq 2) {
            ($staleRestoreState.profiles | Where-Object name -eq 'Domain' | Select-Object -First 1).enabled = $false
        }
        return @($staleRestoreState.profiles)
    }.GetNewClosure()
    $staleRestoreWriterState = @{ calls = 0 }
    $staleRestoreSetter = { param($profiles, $enabled) $staleRestoreWriterState.calls++ }.GetNewClosure()
    $staleRestoreAuditPath = Join-Path $testRoot 'stale-restore-audit.jsonl'
    $staleRestoreRejected = $false
    try {
        Restore-FluxForgeWindowsSecurityPolicy -BackupPath $apply.backupPath -AuditLogPath $staleRestoreAuditPath -Confirmation $restoreConfirmation -StateReader $staleRestoreReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $staleRestoreSetter | Out-Null
    }
    catch {
        $staleRestoreRejected = $_.Exception.Message -match 'state changed after the restore preview'
    }
    $staleRestoreEvents = @(Get-Content -LiteralPath $staleRestoreAuditPath | ForEach-Object { ConvertFrom-Json $_ })
    Assert-True ($staleRestoreRejected -and $staleRestoreWriterState.calls -eq 0) 'A target changed after restore preview must prevent restoration writes.'
    Assert-True (($staleRestoreEvents | Where-Object eventType -eq 'restore_failed').changesMade -eq $false) 'A restore blocked before writing must report changesMade=false.'

    $missingBackupRejected = $false
    try {
        Restore-FluxForgeWindowsSecurityPolicy -BackupPath (Join-Path $testRoot 'missing.json') -AuditLogPath $auditPath -Confirmation 'RESTORE missing' -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $setter | Out-Null
    }
    catch {
        $missingBackupRejected = $_.Exception.Message -match 'verified backup'
    }
    Assert-True $missingBackupRejected 'Restore must refuse when verified recovery information is missing.'

    $tamperedBackup = Join-Path $testRoot 'tampered-backup.json'
    $tampered = Get-Content -LiteralPath $apply.backupPath -Raw | ConvertFrom-Json -AsHashtable
    $tampered.payload.profiles[0].enabled = $true
    $tampered | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $tamperedBackup
    $tamperedRejected = $false
    try {
        Restore-FluxForgeWindowsSecurityPolicy -BackupPath $tamperedBackup -AuditLogPath $auditPath -Confirmation $restoreConfirmation -StateReader $stateReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $setter | Out-Null
    }
    catch {
        $tamperedRejected = $_.Exception.Message -match 'integrity verification'
    }
    Assert-True $tamperedRejected 'Restore must reject a backup whose integrity check fails.'

    $verificationState = @{
        profiles = @(@{ name = 'Domain'; enabled = $false }, @{ name = 'Private'; enabled = $true }, @{ name = 'Public'; enabled = $false })
    }
    $verificationReader = { param($name) if ($name -eq 'Windows Firewall profiles') { @($verificationState.profiles) } else { @{ fixture = $true } } }.GetNewClosure()
    $verificationSetterState = @{ calls = 0 }
    $verificationSetter = { param($profiles, $enabled) $verificationSetterState.calls++; }.GetNewClosure()
    $verificationFailed = $false
    try {
        Set-FluxForgeWindowsSecurityPolicy -PolicyPath $policyPath -BackupDirectory (Join-Path $testRoot 'verification-backup') -AuditLogPath (Join-Path $testRoot 'verification-audit.jsonl') -Confirmation 'APPLY FirewallProfile.Enabled=true' -StateReader $verificationReader -EnvironmentProvider $environment -AdministratorProvider $admin -Setter $verificationSetter | Out-Null
    }
    catch {
        $verificationFailed = $_.Exception.Message -match 'Post-apply verification failed'
    }
    Assert-True ($verificationFailed -and $verificationSetterState.calls -eq 1) 'Failed post-apply verification must be reported as failure.'
    $verificationAudit = Get-Content -LiteralPath (Join-Path $testRoot 'verification-audit.jsonl')
    Assert-True (($verificationAudit | Where-Object { $_ -match 'apply_failed' }).Count -eq 1) 'Verification failures must be written as failed audit events.'

    $unsupportedEnvironmentRejected = $false
    try {
        Get-FluxForgeWindowsPlan -PolicyPath $policyPath -StateReader $stateReader -EnvironmentProvider { [pscustomobject]@{ isWindows = $false; supported = $false; classification = 'LinuxCodespaces' } } | Out-Null
    }
    catch {
        $unsupportedEnvironmentRejected = $_.Exception.Message -match 'Windows 10 or Windows 11'
    }
    Assert-True $unsupportedEnvironmentRejected 'Plan and Apply prerequisites must fail outside supported local Windows.'

    Remove-Module FluxForge.WindowsSecurity -Force
    Write-Host "PASS: $script:testCount Windows security framework assertions passed."
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
