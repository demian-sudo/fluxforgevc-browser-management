[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'

function Get-FluxForgeEnvironment {
    [CmdletBinding()]
    param(
        [ValidateSet('Windows', 'Linux', 'MacOS', 'Unsupported')]
        [string]$Platform,
        [string]$Version,
        [bool]$Codespaces
    )

    if (-not $PSBoundParameters.ContainsKey('Platform')) {
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            $Platform = 'Windows'
        }
        elseif ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)) {
            $Platform = 'Linux'
        }
        elseif ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)) {
            $Platform = 'MacOS'
        }
        else {
            $Platform = 'Unsupported'
        }
    }

    if (-not $PSBoundParameters.ContainsKey('Version')) {
        $Version = [Environment]::OSVersion.Version.ToString()
    }
    if (-not $PSBoundParameters.ContainsKey('Codespaces')) {
        $Codespaces = $Platform -eq 'Linux' -and (
            -not [string]::IsNullOrWhiteSpace($env:CODESPACES) -or
            -not [string]::IsNullOrWhiteSpace($env:CODESPACE_NAME)
        )
    }

    $classification = switch ($Platform) {
        'Windows' {
            $versionParts = $Version.Split('.')
            $build = 0
            if ($versionParts.Count -ge 3 -and [int]::TryParse($versionParts[2], [ref]$build)) {
                if ($build -ge 22000) { 'Windows11' }
                elseif ($build -ge 10240) { 'Windows10' }
                else { 'UnsupportedWindows' }
            }
            else {
                'UnsupportedWindows'
            }
        }
        'Linux' {
            if ($Codespaces) { 'LinuxCodespaces' } else { 'Linux' }
        }
        'MacOS' { 'UnsupportedMacOS' }
        default { 'Unsupported' }
    }

    [pscustomobject][ordered]@{
        classification = $classification
        platform = $Platform
        version = $Version
        isCodespaces = ($Platform -eq 'Linux' -and $Codespaces)
        scope = if ($Platform -eq 'Linux' -and $Codespaces) {
            'Codespaces container; not the developers physical Windows computer.'
        }
        elseif ($Platform -eq 'Windows') {
            'Local Windows computer.'
        }
        elseif ($Platform -eq 'Linux') {
            'Linux host or container; not a Windows host.'
        }
        else {
            'Unsupported environment; Windows-specific checks are unavailable.'
        }
    }
}

function New-FluxForgeAuditCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'FAIL', 'WARNING', 'NOT_VERIFIED')]
        [string]$Status,
        [Parameter(Mandatory)]
        [string]$Explanation,
        [string]$Remediation
    )

    [pscustomobject][ordered]@{
        checkName = $Name
        status = $Status
        explanation = $Explanation
        remediation = $Remediation
    }
}

function Get-FluxForgeCommandAvailability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommandName
    )

    [bool](Get-Command -Name $CommandName -ErrorAction SilentlyContinue)
}

function Add-FluxForgeWindowsChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]]$Checks
    )

    $managementCommands = @('Get-MpComputerStatus', 'Get-NetFirewallProfile', 'Get-BitLockerVolume')
    $availableManagementCommands = @($managementCommands | Where-Object { Get-FluxForgeCommandAvailability -CommandName $_ })
    $managementStatus = if ($availableManagementCommands.Count -eq $managementCommands.Count) {
        'PASS'
    }
    elseif ($availableManagementCommands.Count -gt 0) {
        'WARNING'
    }
    else {
        'NOT_VERIFIED'
    }
    $managementExplanation = if ($availableManagementCommands.Count -gt 0) {
        "Read-only Windows management commands available: $($availableManagementCommands -join ', ')."
    }
    else {
        'No supported Defender, Firewall, or BitLocker read-only management commands were found.'
    }
    $managementRemediation = if ($managementStatus -eq 'PASS') { $null } else { 'Review required Windows management modules and organizational tooling; this audit does not install software.' }
    $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows management tooling availability' -Status $managementStatus -Explanation $managementExplanation -Remediation $managementRemediation))

    if (-not (Get-FluxForgeCommandAvailability -CommandName Get-MpComputerStatus)) {
        $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Defender status' -Status NOT_VERIFIED -Explanation 'Get-MpComputerStatus is unavailable in this PowerShell environment.' -Remediation 'Use a supported Windows installation with the Windows Defender module available; do not enable or change protections through this audit.'))
    }
    else {
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            $defenderEnabled = [bool]$defender.AntivirusEnabled
            $realTimeEnabled = [bool]$defender.RealTimeProtectionEnabled
            $status = if ($defenderEnabled -and $realTimeEnabled) { 'PASS' } else { 'WARNING' }
            $explanation = "Antivirus enabled: $defenderEnabled; real-time protection enabled: $realTimeEnabled."
            $remediation = if ($status -eq 'PASS') { $null } else { 'Review Windows Security and organizational endpoint-protection policy with an administrator.' }
            $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Defender status' -Status $status -Explanation $explanation -Remediation $remediation))
        }
        catch {
            $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Defender status' -Status NOT_VERIFIED -Explanation 'Windows Defender status could not be read in the current context.' -Remediation 'Review Windows Security permissions; run an elevated audit only if your administrator approves.'))
        }
    }

    if (-not (Get-FluxForgeCommandAvailability -CommandName Get-NetFirewallProfile)) {
        $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Firewall profiles' -Status NOT_VERIFIED -Explanation 'Get-NetFirewallProfile is unavailable in this PowerShell environment.' -Remediation 'Use a supported Windows installation with the NetSecurity module available.'))
    }
    else {
        try {
            $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
            if ($profiles.Count -eq 0) {
                $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Firewall profiles' -Status NOT_VERIFIED -Explanation 'No firewall profiles were returned.' -Remediation 'Review firewall status in Windows Security or with an authorized administrator.'))
            }
            else {
                $disabledProfiles = @($profiles | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name })
                $status = if ($disabledProfiles.Count -eq 0) { 'PASS' } else { 'WARNING' }
                $explanation = if ($disabledProfiles.Count -eq 0) {
                    "Firewall is enabled for $($profiles.Count) reported profile(s)."
                }
                else {
                    "Firewall is disabled for $($disabledProfiles.Count) reported profile(s): $($disabledProfiles -join ', ')."
                }
                $remediation = if ($status -eq 'PASS') { $null } else { 'Review firewall profiles and organizational policy; this audit does not change rules or profiles.' }
                $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Firewall profiles' -Status $status -Explanation $explanation -Remediation $remediation))
            }
        }
        catch {
            $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Firewall profiles' -Status NOT_VERIFIED -Explanation 'Firewall profile information could not be read in the current context.' -Remediation 'Review NetSecurity access; run an elevated audit only if your administrator approves.'))
        }
    }

    if (-not (Get-FluxForgeCommandAvailability -CommandName Get-Service)) {
        $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Update service' -Status NOT_VERIFIED -Explanation 'Get-Service is unavailable in this PowerShell environment.' -Remediation 'Run the audit using supported Windows PowerShell tooling.'))
    }
    else {
        try {
            $updateService = Get-Service -Name wuauserv -ErrorAction Stop
            $status = if ($updateService.Status -eq 'Running') { 'PASS' } else { 'WARNING' }
            $explanation = "Windows Update service status: $($updateService.Status)."
            $remediation = if ($status -eq 'PASS') { $null } else { 'Review Windows Update configuration with an administrator; this audit does not start or reconfigure services.' }
            $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Update service' -Status $status -Explanation $explanation -Remediation $remediation))
        }
        catch {
            $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows Update service' -Status NOT_VERIFIED -Explanation 'Windows Update service status could not be read.' -Remediation 'Review service access and Windows Update configuration with an administrator.'))
        }
    }

    if (-not (Get-FluxForgeCommandAvailability -CommandName Get-BitLockerVolume)) {
        $Checks.Add((New-FluxForgeAuditCheck -Name 'BitLocker availability and encryption' -Status NOT_VERIFIED -Explanation 'Get-BitLockerVolume is unavailable; BitLocker state was not queried.' -Remediation 'Use supported Windows tooling and review drive encryption with an authorized administrator.'))
    }
    else {
        try {
            $systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
            $volume = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop
            $encrypted = [string]$volume.VolumeStatus -eq 'FullyEncrypted'
            $protected = [string]$volume.ProtectionStatus -eq 'On'
            $status = if ($encrypted -and $protected) { 'PASS' } else { 'WARNING' }
            $explanation = "System volume status: $($volume.VolumeStatus); protection status: $($volume.ProtectionStatus); encryption percentage: $($volume.EncryptionPercentage)."
            $remediation = if ($status -eq 'PASS') { $null } else { 'Review device encryption requirements and recovery procedures with an authorized administrator; this audit does not change BitLocker.' }
            $Checks.Add((New-FluxForgeAuditCheck -Name 'BitLocker availability and encryption' -Status $status -Explanation $explanation -Remediation $remediation))
        }
        catch {
            $Checks.Add((New-FluxForgeAuditCheck -Name 'BitLocker availability and encryption' -Status NOT_VERIFIED -Explanation 'BitLocker state could not be read; no recovery keys or volume identifiers were collected.' -Remediation 'Review BitLocker access and permissions with an authorized administrator.'))
        }
    }

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $status = if ($isAdministrator) { 'PASS' } else { 'WARNING' }
        $explanation = if ($isAdministrator) { 'The current PowerShell process is elevated.' } else { 'The current PowerShell process is not elevated; some Windows checks may be unavailable.' }
        $remediation = if ($isAdministrator) { $null } else { 'No elevation is attempted. If required, rerun in an administrator shell only with explicit approval.' }
        $Checks.Add((New-FluxForgeAuditCheck -Name 'Administrator privileges' -Status $status -Explanation $explanation -Remediation $remediation))
    }
    catch {
        $Checks.Add((New-FluxForgeAuditCheck -Name 'Administrator privileges' -Status NOT_VERIFIED -Explanation 'The current privilege level could not be determined.' -Remediation 'No elevation is attempted; check the shell security context manually.'))
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build = [int]$os.BuildNumber
        $version = [version]$os.Version
        $classification = if ($version.Major -eq 10 -and $build -ge 22000) { 'Windows11' } elseif ($version.Major -eq 10 -and $build -ge 10240) { 'Windows10' } else { 'UnsupportedWindows' }
        $status = if ($classification -in @('Windows10', 'Windows11')) { 'PASS' } else { 'WARNING' }
        $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows OS version' -Status $status -Explanation "Detected $classification (version $($os.Version), build $build)." -Remediation $(if ($status -eq 'PASS') { $null } else { 'Use a supported Windows 10 or Windows 11 environment.' })))
    }
    catch {
        $Checks.Add((New-FluxForgeAuditCheck -Name 'Windows OS version' -Status NOT_VERIFIED -Explanation 'Windows OS version could not be read.' -Remediation 'Review Windows CIM access and system support with an administrator.'))
    }
}

function Get-FluxForgeEnvironmentAudit {
    [CmdletBinding()]
    param(
        [string]$OutputDirectory,
        [object]$Environment = (Get-FluxForgeEnvironment),
        [scriptblock]$WindowsCheckRunner
    )

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $OutputDirectory = Join-Path $repositoryRoot 'reports/environment-audit'
    }

    $checks = [System.Collections.Generic.List[object]]::new()
    $isSupportedWindows = $Environment.classification -in @('Windows10', 'Windows11')
    if ($isSupportedWindows) {
        if ($WindowsCheckRunner) {
            & $WindowsCheckRunner $checks
        }
        else {
            Add-FluxForgeWindowsChecks -Checks $checks
        }
    }
    else {
        $message = if ($Environment.classification -eq 'LinuxCodespaces') {
            'Not run: this Codespaces container is Linux and cannot inspect the host computer.'
        }
        elseif ($Environment.classification -eq 'Linux') {
            'Not run: this environment is Linux, not a local Windows installation.'
        }
        else {
            'Not run: Windows security checks are supported only on Windows 10 or Windows 11.'
        }
        foreach ($checkName in @('Windows Defender status', 'Windows Firewall profiles', 'Windows Update service', 'BitLocker availability and encryption')) {
            $checks.Add((New-FluxForgeAuditCheck -Name $checkName -Status NOT_VERIFIED -Explanation $message -Remediation 'Run this audit locally on the Windows computer to inspect Windows-only state.'))
        }
        $checks.Add((New-FluxForgeAuditCheck -Name 'Windows management tooling availability' -Status NOT_VERIFIED -Explanation $message -Remediation 'Run this audit locally on the Windows computer to inspect installed Windows management tools.'))
    }

    $checks.Add((New-FluxForgeAuditCheck -Name 'PowerShell version' -Status $(if ($PSVersionTable.PSVersion -ge [version]'7.4') { 'PASS' } else { 'WARNING' }) -Explanation "PowerShell $($PSVersionTable.PSVersion); edition $($PSVersionTable.PSEdition)." -Remediation $(if ($PSVersionTable.PSVersion -ge [version]'7.4') { $null } else { 'Use PowerShell 7.4 or later for repository tooling.' })))

    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication -ErrorAction SilentlyContinue | Select-Object -First 1
    $checks.Add((New-FluxForgeAuditCheck -Name 'Microsoft Graph Authentication module' -Status $(if ($graphModule) { 'PASS' } else { 'NOT_VERIFIED' }) -Explanation $(if ($graphModule) { "Module is installed (version $($graphModule.Version)); no Graph connection was attempted." } else { 'Microsoft.Graph.Authentication is not installed; no Graph connection was attempted.' }) -Remediation $(if ($graphModule) { $null } else { 'Install only from an organization-approved repository if read-only Graph work is authorized.' })))

    $gitAvailable = Get-FluxForgeCommandAvailability -CommandName git
    $checks.Add((New-FluxForgeAuditCheck -Name 'Git availability' -Status $(if ($gitAvailable) { 'PASS' } else { 'WARNING' }) -Explanation $(if ($gitAvailable) { 'The git command is available.' } else { 'The git command is unavailable in PATH.' }) -Remediation $(if ($gitAvailable) { $null } else { 'Install Git from an approved source if repository operations are needed.' })))

    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $testPath = Join-Path $repositoryRoot 'tests/Test-FluxForgePolicyFoundation.ps1'
    $testFound = Test-Path -LiteralPath $testPath -PathType Leaf
    $checks.Add((New-FluxForgeAuditCheck -Name 'Repository offline tests' -Status $(if ($testFound) { 'PASS' } else { 'WARNING' }) -Explanation $(if ($testFound) { 'The policy foundation offline test script was found in this repository.' } else { 'The policy foundation offline test script was not found at the expected repository path.' }) -Remediation $(if ($testFound) { $null } else { 'Run the audit from a repository checkout containing the tests directory.' })))

    $report = [pscustomobject][ordered]@{
        reportVersion = '1.0'
        generatedAtUtc = [datetime]::UtcNow.ToString('o')
        operatingSystem = $Environment
        auditMode = 'read-only'
        providerContacted = $false
        changesMade = $false
        checks = @($checks.ToArray())
    }

    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop
    $reportPath = Join-Path $OutputDirectory "FluxForge-Environment-Audit-$([datetime]::UtcNow.ToString('yyyyMMdd-HHmmssfff')).json"
    $json = ConvertTo-Json -InputObject $report -Depth 20
    [System.IO.File]::WriteAllText($reportPath, $json, [System.Text.UTF8Encoding]::new($false))
    $report | Add-Member -NotePropertyName reportPath -NotePropertyValue $reportPath
    $report
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $report = Get-FluxForgeEnvironmentAudit -OutputDirectory $OutputDirectory
        if ($AsJson) {
            $report | ConvertTo-Json -Depth 20
        }
        else {
            $report.checks | Format-Table -Property checkName, status, explanation -Wrap
            Write-Output "JSON report: $($report.reportPath)"
        }
    }
    catch {
        Write-Error "Environment audit failed: $($_.Exception.Message)"
        exit 1
    }
}
