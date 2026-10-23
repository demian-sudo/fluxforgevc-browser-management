Set-StrictMode -Version Latest

$script:SupportedProfiles = @('Domain', 'Private', 'Public')
$script:WritableSetting = 'FirewallProfile.Enabled'

function Get-FluxForgeWindowsEnvironment {
    [CmdletBinding()]
    param(
        [scriptblock]$EnvironmentProvider
    )

    if ($EnvironmentProvider) {
        return & $EnvironmentProvider
    }

    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        return [pscustomobject]@{ isWindows = $false; supported = $false; classification = 'Unsupported' }
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $version = [version]$os.Version
        $build = [int]$os.BuildNumber
        $classification = if ($version.Major -eq 10 -and $build -ge 22000) {
            'Windows11'
        }
        elseif ($version.Major -eq 10 -and $build -ge 10240) {
            'Windows10'
        }
        else {
            'UnsupportedWindows'
        }
        [pscustomobject]@{
            isWindows = $true
            supported = $classification -in @('Windows10', 'Windows11')
            classification = $classification
        }
    }
    catch {
        [pscustomobject]@{ isWindows = $true; supported = $false; classification = 'WindowsVersionNotVerified' }
    }
}

function Get-FluxForgeWindowsAdministratorStatus {
    [CmdletBinding()]
    param(
        [scriptblock]$AdministratorProvider
    )

    if ($AdministratorProvider) {
        try {
            $isAdministrator = [bool](& $AdministratorProvider)
            if ($isAdministrator) { return 'PASS' }
            return 'FAIL'
        }
        catch {
            return 'NOT_VERIFIED'
        }
    }
    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        return 'NOT_VERIFIED'
    }
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { return 'PASS' }
        return 'FAIL'
    }
    catch {
        return 'NOT_VERIFIED'
    }
}

function Test-FluxForgeWindowsAdministrator {
    [CmdletBinding()]
    param(
        [scriptblock]$AdministratorProvider
    )

    return (Get-FluxForgeWindowsAdministratorStatus -AdministratorProvider $AdministratorProvider) -eq 'PASS'
}

function Get-FluxForgeNativeWindowsState {
    param([Parameter(Mandatory)][string]$Name)

    switch ($Name) {
        'Windows Defender status' {
            if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { throw 'Defender cmdlet unavailable.' }
            $status = Get-MpComputerStatus -ErrorAction Stop
            return [pscustomobject]@{
                antivirusEnabled = [bool]$status.AntivirusEnabled
                realTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
                behaviorMonitorEnabled = [bool]$status.BehaviorMonitorEnabled
                antispywareEnabled = [bool]$status.AntispywareEnabled
            }
        }
        'Windows Firewall profiles' {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { throw 'Firewall cmdlet unavailable.' }
            return @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled }
            })
        }
        'Windows Update configuration visibility' {
            $service = Get-Service -Name wuauserv -ErrorAction Stop
            [pscustomobject]@{ serviceStatus = [string]$service.Status; startType = [string]$service.StartType }
        }
        'PowerShell security configuration visibility' {
            $executionPolicies = @(Get-ExecutionPolicy -List | ForEach-Object {
                [pscustomobject]@{ scope = [string]$_.Scope; policy = [string]$_.ExecutionPolicy }
            })
            [pscustomobject]@{
                edition = [string]$PSVersionTable.PSEdition
                version = [string]$PSVersionTable.PSVersion
                languageMode = [string]$ExecutionContext.SessionState.LanguageMode
                executionPolicies = $executionPolicies
            }
        }
        'Browser policy configuration visibility' {
            $paths = @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
                'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
                'HKLM:\SOFTWARE\Policies\Google\Chrome',
                'HKCU:\SOFTWARE\Policies\Google\Chrome'
            )
            $present = @($paths | Where-Object { Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue })
            [pscustomobject]@{
                edgePolicyConfigured = @($present | Where-Object { $_ -match '\\Edge$' }).Count -gt 0
                chromePolicyConfigured = @($present | Where-Object { $_ -match '\\Chrome$' }).Count -gt 0
            }
        }
        'BitLocker status and availability' {
            if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { throw 'BitLocker cmdlet unavailable.' }
            $mountPoint = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
            $volume = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
            [pscustomobject]@{
                volumeStatus = [string]$volume.VolumeStatus
                protectionStatus = [string]$volume.ProtectionStatus
                encryptionPercentage = [int]$volume.EncryptionPercentage
            }
        }
        default { throw 'Unsupported Windows state check.' }
    }
}

function Get-FluxForgeWindowsSecurityState {
    [CmdletBinding()]
    param(
        [scriptblock]$StateReader,
        [scriptblock]$EnvironmentProvider,
        [scriptblock]$AdministratorProvider
    )

    $environment = Get-FluxForgeWindowsEnvironment -EnvironmentProvider $EnvironmentProvider
    $checks = [System.Collections.Generic.List[object]]::new()
    $names = @(
        'Windows Defender status',
        'Windows Firewall profiles',
        'Windows Update configuration visibility',
        'PowerShell security configuration visibility',
        'Browser policy configuration visibility',
        'BitLocker status and availability'
    )

    foreach ($name in $names) {
        if (-not $environment.supported) {
            $checks.Add([pscustomobject]@{
                checkName = $name
                status = 'NOT_VERIFIED'
                value = $null
                explanation = 'Windows security state is unavailable outside supported local Windows 10/11.'
            })
            continue
        }
        try {
            $value = if ($StateReader) { & $StateReader $name } else { Get-FluxForgeNativeWindowsState -Name $name }
            if ($null -eq $value) { throw 'State unavailable.' }
            $checks.Add([pscustomobject]@{
                checkName = $name
                status = 'PASS'
                value = $value
                explanation = 'Read-only local state was retrieved.'
            })
        }
        catch {
            $checks.Add([pscustomobject]@{
                checkName = $name
                status = 'NOT_VERIFIED'
                value = $null
                explanation = 'State could not be read with the available commands or permissions.'
            })
        }
    }

    [pscustomobject]@{
        generatedAtUtc = [datetime]::UtcNow.ToString('o')
        operatingSystem = $environment.classification
        supportedWindows = [bool]$environment.supported
        administratorStatus = Get-FluxForgeWindowsAdministratorStatus -AdministratorProvider $AdministratorProvider
        checks = @($checks.ToArray())
    }
}

function Get-FluxForgeWindowsPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyPath
    )

    if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
        throw 'Policy file was not found.'
    }
    $document = Get-Content -LiteralPath $PolicyPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -Depth 20 -ErrorAction Stop
    if ($document -isnot [System.Collections.IDictionary] -or
        @($document.Keys | Where-Object { $_ -cnotin @('schemaVersion', 'settings') }).Count -gt 0 -or
        @(@('schemaVersion', 'settings') | Where-Object { $_ -cnotin @($document.Keys) }).Count -gt 0 -or
        $document.schemaVersion -cne '1.0' -or $document.settings -isnot [array] -or $document.settings.Count -eq 0) {
        throw 'Policy must use schemaVersion 1.0 and include a non-empty settings array.'
    }
    $seenProfiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($setting in $document.settings) {
        if ($setting -isnot [System.Collections.IDictionary] -or
            @($setting.Keys | Where-Object { $_ -cnotin @('name', 'profiles', 'value') }).Count -gt 0 -or
            @(@('name', 'profiles', 'value') | Where-Object { $_ -cnotin @($setting.Keys) }).Count -gt 0) {
            throw 'Each policy setting must include only name, profiles, and value.'
        }
        if ($setting.name -cne $script:WritableSetting -or $setting.value -isnot [bool] -or -not $setting.value) {
            throw 'Only FirewallProfile.Enabled=true is currently supported for Apply.'
        }
        if ($setting.profiles -isnot [array] -or $setting.profiles.Count -eq 0 -or
            @($setting.profiles | Where-Object { $_ -cnotin $script:SupportedProfiles }).Count -gt 0) {
            throw 'Firewall policy profiles must be a non-empty, unique list of Domain, Private, or Public.'
        }
        foreach ($profileName in $setting.profiles) {
            if (-not $seenProfiles.Add([string]$profileName)) {
                throw 'Firewall profiles may be assigned only once in a policy.'
            }
        }
    }
    return $document
}

function Get-FluxForgeFirewallProfiles {
    param(
        [scriptblock]$StateReader
    )

    $state = if ($StateReader) {
        & $StateReader 'Windows Firewall profiles'
    }
    else {
        Get-FluxForgeNativeWindowsState -Name 'Windows Firewall profiles'
    }
    if ($null -eq $state) { throw 'Firewall profile state is unavailable.' }
    $profiles = @($state)
    if ($profiles.Count -eq 0) { throw 'Firewall profile state is empty or unavailable.' }
    foreach ($profile in $profiles) {
        if ($profile.name -notin $script:SupportedProfiles -or $null -eq $profile.enabled) {
            throw 'Firewall profile state is incomplete or contains an unsupported profile.'
        }
    }
    return $profiles
}

function Write-FluxForgeWindowsAuditEvent {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('plan_created', 'apply_denied', 'apply_started', 'apply_completed', 'apply_failed', 'restore_denied', 'restore_started', 'restore_completed', 'restore_failed')][string]$EventType,
        [Parameter(Mandatory)][ValidateSet('planned', 'started', 'completed', 'failed')][string]$Outcome,
        [Parameter(Mandatory)][string]$Setting,
        [bool]$ChangesMade = $false
    )

    $directory = Split-Path -Parent $Path
    if ($directory) { $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop }
    $event = [ordered]@{
        timestamp = [datetime]::UtcNow.ToString('o')
        eventType = $EventType
        outcome = $Outcome
        setting = $Setting
        changesMade = $ChangesMade
    }
    [System.IO.File]::AppendAllText($Path, (ConvertTo-Json -InputObject $event -Compress) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function Get-FluxForgeWindowsBackupHash {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Payload
    )

    $timestamp = ([string]$Payload.createdAtUtc) -replace '^UTC:', ''
    $createdAtUtc = 'UTC:' + [datetime]::Parse(
        $timestamp,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    ).ToUniversalTime().ToString('o')
    $canonicalPayload = [ordered]@{
        backupVersion = [string]$Payload.backupVersion
        backupId = [string]$Payload.backupId
        createdAtUtc = $createdAtUtc
        operatingSystem = [string]$Payload.operatingSystem
        setting = [string]$Payload.setting
        profiles = @($Payload.profiles | ForEach-Object {
            [ordered]@{
                name = [string]$_.name
                enabled = [bool]$_.enabled
            }
        })
    }
    $canonicalJson = ConvertTo-Json -InputObject $canonicalPayload -Depth 10 -Compress
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonicalJson)))
}

function Get-FluxForgeWindowsPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PolicyPath,
        [scriptblock]$StateReader,
        [scriptblock]$EnvironmentProvider
    )

    $environment = Get-FluxForgeWindowsEnvironment -EnvironmentProvider $EnvironmentProvider
    if (-not $environment.supported) { throw 'Plan requires verified Windows 10 or Windows 11.' }
    $policy = Get-FluxForgeWindowsPolicy -PolicyPath $PolicyPath
    $profiles = Get-FluxForgeFirewallProfiles -StateReader $StateReader
    $changes = [System.Collections.Generic.List[object]]::new()
    foreach ($setting in $policy.settings) {
        foreach ($profileName in $setting.profiles) {
            $profile = $profiles | Where-Object { $_.name -eq $profileName } | Select-Object -First 1
            if (-not $profile) { throw 'A requested firewall profile could not be verified.' }
            $changes.Add([pscustomobject]@{
                setting = $script:WritableSetting
                profile = $profileName
                previousValue = [bool]$profile.enabled
                intendedValue = [bool]$setting.value
                changesRequired = -not [bool]$profile.enabled
                rollbackSupported = $true
            })
        }
    }
    [pscustomobject]@{
        mode = 'Plan'
        operatingSystem = $environment.classification
        changes = @($changes.ToArray())
        changesMade = $false
    }
}

function Set-FluxForgeWindowsSecurityPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PolicyPath,
        [Parameter(Mandatory)][string]$BackupDirectory,
        [Parameter(Mandatory)][string]$AuditLogPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Confirmation,
        [scriptblock]$StateReader,
        [scriptblock]$EnvironmentProvider,
        [scriptblock]$AdministratorProvider,
        [scriptblock]$Setter
    )

    $plan = Get-FluxForgeWindowsPlan -PolicyPath $PolicyPath -StateReader $StateReader -EnvironmentProvider $EnvironmentProvider
    Write-Host 'Exact change preview:'
    $plan.changes | Format-Table -Property setting, profile, previousValue, intendedValue, changesRequired -AutoSize
    $changes = @($plan.changes | Where-Object changesRequired)
    $expectedConfirmation = 'APPLY FirewallProfile.Enabled=true'
    if ($Confirmation -cne $expectedConfirmation) {
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType apply_denied -Outcome failed -Setting $script:WritableSetting
        throw "Apply refused. Review the plan and supply the exact confirmation: $expectedConfirmation"
    }
    if (-not (Test-FluxForgeWindowsAdministrator -AdministratorProvider $AdministratorProvider)) {
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType apply_denied -Outcome failed -Setting $script:WritableSetting
        throw 'Apply requires administrator privileges; no elevation will be attempted.'
    }
    if (-not $Setter -and -not (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw 'Set-NetFirewallProfile is unavailable; no changes were made.'
    }

    $backupId = [guid]::NewGuid().ToString('N')
    $payload = [ordered]@{
        backupVersion = '1.0'
        backupId = $backupId
        createdAtUtc = 'UTC:' + [datetime]::UtcNow.ToString('o')
        operatingSystem = $plan.operatingSystem
        setting = $script:WritableSetting
        profiles = @($plan.changes | ForEach-Object {
            [pscustomobject]@{ name = $_.profile; enabled = [bool]$_.previousValue }
        })
    }
    $checksum = Get-FluxForgeWindowsBackupHash -Payload $payload
    $backup = [ordered]@{ payload = $payload; sha256 = $checksum }
    $null = New-Item -ItemType Directory -Path $BackupDirectory -Force -ErrorAction Stop
    $backupPath = Join-Path $BackupDirectory "FluxForge-Windows-Backup-$backupId.json"
    [System.IO.File]::WriteAllText($backupPath, (ConvertTo-Json -InputObject $backup -Depth 10), [System.Text.UTF8Encoding]::new($false))

    $settingSummary = ($plan.changes | ForEach-Object { "$($_.profile)=$($_.intendedValue)" }) -join ','
    Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType apply_started -Outcome started -Setting "$script:WritableSetting [$settingSummary]"
    $writerInvoked = $false
    try {
        if ($changes.Count -gt 0) {
            $currentProfiles = Get-FluxForgeFirewallProfiles -StateReader $StateReader
            $stalePlan = @($plan.changes | Where-Object {
                $expectedName = $_.profile
                $current = $currentProfiles | Where-Object { $_.name -eq $expectedName } | Select-Object -First 1
                -not $current -or [bool]$current.enabled -ne [bool]$_.previousValue
            })
            if ($stalePlan.Count -gt 0) { throw 'Firewall state changed after the preview; no changes were made. Create a new plan.' }
            $profileNames = @($changes.profile)
            $writerInvoked = $true
            if ($Setter) { & $Setter $profileNames $true }
            else { Set-NetFirewallProfile -Profile $profileNames -Enabled $true -ErrorAction Stop }
        }
        $verifiedProfiles = Get-FluxForgeFirewallProfiles -StateReader $StateReader
        $failed = @($plan.changes | Where-Object {
            $expectedName = $_.profile
            $verified = $verifiedProfiles | Where-Object { $_.name -eq $expectedName } | Select-Object -First 1
            -not $verified -or -not [bool]$verified.enabled
        })
        if ($failed.Count -gt 0) { throw 'Post-apply verification failed for one or more firewall profiles.' }
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType apply_completed -Outcome completed -Setting $script:WritableSetting -ChangesMade ($changes.Count -gt 0)
        [pscustomobject]@{
            status = 'PASS'
            mode = 'Apply'
            backupPath = $backupPath
            changes = @($plan.changes)
            changesMade = ($changes.Count -gt 0)
        }
    }
    catch {
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType apply_failed -Outcome failed -Setting $script:WritableSetting -ChangesMade $writerInvoked
        throw
    }
}

function Restore-FluxForgeWindowsSecurityPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BackupPath,
        [Parameter(Mandatory)][string]$AuditLogPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Confirmation,
        [scriptblock]$StateReader,
        [scriptblock]$EnvironmentProvider,
        [scriptblock]$AdministratorProvider,
        [scriptblock]$Setter
    )

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { throw 'Restore refused: verified backup file was not found.' }
    $backup = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -Depth 10 -ErrorAction Stop
    if (-not $backup.payload -or $backup.payload.backupVersion -ne '1.0' -or
        $backup.payload.setting -ne $script:WritableSetting -or
        [string]::IsNullOrWhiteSpace([string]$backup.payload.backupId) -or
        [string]::IsNullOrWhiteSpace([string]$backup.payload.createdAtUtc) -or
        [string]::IsNullOrWhiteSpace([string]$backup.payload.operatingSystem) -or
        $backup.payload.profiles -isnot [array] -or $backup.payload.profiles.Count -eq 0) {
        throw 'Restore refused: backup structure or supported setting is invalid.'
    }
    foreach ($profile in $backup.payload.profiles) {
        if ($profile -isnot [System.Collections.IDictionary] -or
            -not $profile.Contains('name') -or -not $profile.Contains('enabled') -or
            $profile.name -notin $script:SupportedProfiles -or $profile.enabled -isnot [bool]) {
            throw 'Restore refused: backup contains unsupported or invalid profile state.'
        }
    }
    if (@($backup.payload.profiles | ForEach-Object { $_.name } | Select-Object -Unique).Count -ne $backup.payload.profiles.Count) {
        throw 'Restore refused: backup contains duplicate profile entries.'
    }
    $expectedHash = Get-FluxForgeWindowsBackupHash -Payload $backup.payload
    if ($backup.sha256 -cne $expectedHash) { throw 'Restore refused: backup integrity verification failed.' }
    $environment = Get-FluxForgeWindowsEnvironment -EnvironmentProvider $EnvironmentProvider
    if (-not $environment.supported -or $environment.classification -ne $backup.payload.operatingSystem) {
        throw 'Restore requires the same verified supported Windows classification recorded in the backup.'
    }
    if (-not (Test-FluxForgeWindowsAdministrator -AdministratorProvider $AdministratorProvider)) {
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType restore_denied -Outcome failed -Setting $script:WritableSetting
        throw 'Restore requires administrator privileges; no elevation will be attempted.'
    }
    if (-not $Setter -and -not (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw 'Set-NetFirewallProfile is unavailable; restore cannot proceed.'
    }
    $currentProfiles = Get-FluxForgeFirewallProfiles -StateReader $StateReader
    $restorePreview = [System.Collections.Generic.List[object]]::new()
    foreach ($profile in $backup.payload.profiles) {
        $current = $currentProfiles | Where-Object { $_.name -eq $profile.name } | Select-Object -First 1
        if (-not $current) {
            throw 'Restore refused: current state for a requested firewall profile could not be verified.'
        }
        $restorePreview.Add([pscustomobject]@{
            setting = $script:WritableSetting
            profile = $profile.name
            currentValue = [bool]$current.enabled
            restoreValue = [bool]$profile.enabled
        })
    }
    $restoreChanges = @($restorePreview.ToArray() | Where-Object { $_.currentValue -ne $_.restoreValue })
    Write-Host 'Exact restore preview:'
    $restorePreview.ToArray() | Format-Table -Property setting, profile, currentValue, restoreValue -AutoSize
    Write-Host "Required confirmation: RESTORE $($backup.payload.backupId)"
    $expectedRestoreConfirmation = "RESTORE $($backup.payload.backupId)"
    if ($Confirmation -cne $expectedRestoreConfirmation) {
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType restore_denied -Outcome failed -Setting $script:WritableSetting
        throw "Restore refused. Supply the exact confirmation: $expectedRestoreConfirmation"
    }
    Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType restore_started -Outcome started -Setting $script:WritableSetting
    $writerInvoked = $false
    try {
        $preRestoreProfiles = Get-FluxForgeFirewallProfiles -StateReader $StateReader
        $stateChanged = @($restorePreview.ToArray() | Where-Object {
            $expectedName = $_.profile
            $current = $preRestoreProfiles | Where-Object { $_.name -eq $expectedName } | Select-Object -First 1
            -not $current -or [bool]$current.enabled -ne [bool]$_.currentValue
        })
        if ($stateChanged.Count -gt 0) { throw 'Firewall state changed after the restore preview; no changes were made. Review current state again.' }
        foreach ($profile in $restoreChanges) {
            if ($Setter) {
                $profileNames = @([string]$profile.profile)
                $writerInvoked = $true
                & $Setter $profileNames ([bool]$profile.restoreValue)
            }
            else {
                $writerInvoked = $true
                Set-NetFirewallProfile -Profile $profile.profile -Enabled ([bool]$profile.restoreValue) -ErrorAction Stop
            }
        }
        $verifiedProfiles = Get-FluxForgeFirewallProfiles -StateReader $StateReader
        $failed = @($backup.payload.profiles | Where-Object {
            $expectedName = $_.name
            $verified = $verifiedProfiles | Where-Object { $_.name -eq $expectedName } | Select-Object -First 1
            -not $verified -or [bool]$verified.enabled -ne [bool]$_.enabled
        })
        if ($failed.Count -gt 0) { throw 'Restore verification failed for one or more firewall profiles.' }
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType restore_completed -Outcome completed -Setting $script:WritableSetting -ChangesMade ($restoreChanges.Count -gt 0)
        [pscustomobject]@{ status = 'PASS'; mode = 'Restore'; backupId = $backup.payload.backupId; changesMade = ($restoreChanges.Count -gt 0) }
    }
    catch {
        Write-FluxForgeWindowsAuditEvent -Path $AuditLogPath -EventType restore_failed -Outcome failed -Setting $script:WritableSetting -ChangesMade $writerInvoked
        throw
    }
}

Export-ModuleMember -Function @(
    'Get-FluxForgeWindowsSecurityState',
    'Get-FluxForgeWindowsPlan',
    'Set-FluxForgeWindowsSecurityPolicy',
    'Restore-FluxForgeWindowsSecurityPolicy',
    'Write-FluxForgeWindowsAuditEvent'
)
