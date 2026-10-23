[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$auditScript = Join-Path $projectRoot 'scripts/audit/Test-FluxForgeEnvironment.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "FluxForgeEnvironmentAudit-$([guid]::NewGuid().ToString('N'))"
$script:testCount = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
    $script:testCount++
}

try {
    . $auditScript

    $windows10 = Get-FluxForgeEnvironment -Platform Windows -Version '10.0.19045.0' -Codespaces $false
    $windows11 = Get-FluxForgeEnvironment -Platform Windows -Version '10.0.22631.0' -Codespaces $false
    $unsupportedWindows = Get-FluxForgeEnvironment -Platform Windows -Version '6.3.9600.0' -Codespaces $false
    $codespaces = Get-FluxForgeEnvironment -Platform Linux -Version '6.8.0' -Codespaces $true
    $linux = Get-FluxForgeEnvironment -Platform Linux -Version '6.8.0' -Codespaces $false
    $unsupported = Get-FluxForgeEnvironment -Platform MacOS -Version '14.0' -Codespaces $false

    Assert-True ($windows10.classification -eq 'Windows10' -and $windows10.scope -eq 'Local Windows computer.') 'Windows 10 builds must classify as a local Windows environment.'
    Assert-True ($windows11.classification -eq 'Windows11' -and $windows11.scope -eq 'Local Windows computer.') 'Windows 11 builds must classify as a local Windows environment.'
    Assert-True ($unsupportedWindows.classification -eq 'UnsupportedWindows') 'Unsupported legacy Windows versions must not be classified as Windows 10.'
    Assert-True ($codespaces.classification -eq 'LinuxCodespaces' -and $codespaces.isCodespaces -and $codespaces.scope -match 'not the developers physical Windows computer') 'Codespaces must be distinguished from physical Windows.'
    Assert-True ($linux.classification -eq 'Linux' -and -not $linux.isCodespaces) 'Non-Codespaces Linux must be classified separately.'
    Assert-True ($unsupported.classification -eq 'UnsupportedMacOS') 'Unsupported operating systems must be identified.'

    $passCheck = New-FluxForgeAuditCheck -Name 'fixture' -Status PASS -Explanation 'read-only test'
    $warningCheck = New-FluxForgeAuditCheck -Name 'fixture-warning' -Status WARNING -Explanation 'needs review' -Remediation 'Review locally.'
    $notVerifiedCheck = New-FluxForgeAuditCheck -Name 'fixture-unknown' -Status NOT_VERIFIED -Explanation 'not observed'
    Assert-True ($passCheck.status -eq 'PASS' -and $warningCheck.status -eq 'WARNING' -and $notVerifiedCheck.status -eq 'NOT_VERIFIED') 'Audit results must support the documented status classification.'
    $invalidStatusRejected = $false
    try {
        New-FluxForgeAuditCheck -Name 'fixture-invalid' -Status 'UNKNOWN' -Explanation 'invalid' | Out-Null
    }
    catch {
        $invalidStatusRejected = $true
    }
    Assert-True $invalidStatusRejected 'Unknown statuses must be rejected rather than silently accepted.'

    $null = New-Item -ItemType Directory -Path $testRoot -Force
    $linuxReport = Get-FluxForgeEnvironmentAudit -OutputDirectory (Join-Path $testRoot 'linux-report') -Environment $codespaces
    $savedReport = Get-Content -LiteralPath $linuxReport.reportPath -Raw | ConvertFrom-Json
    $windowsOnlyChecks = @($savedReport.checks | Where-Object { $_.checkName -in @('Windows Defender status', 'Windows Firewall profiles', 'Windows Update service', 'BitLocker availability and encryption') })
    Assert-True ($savedReport.operatingSystem.classification -eq 'LinuxCodespaces' -and $savedReport.providerContacted -eq $false -and $savedReport.changesMade -eq $false) 'The report must record Codespaces scope and read-only boundaries.'
    Assert-True ($windowsOnlyChecks.Count -eq 4 -and @($windowsOnlyChecks | Where-Object { $_.status -ne 'NOT_VERIFIED' }).Count -eq 0) 'Windows security checks must remain not verified inside Codespaces.'
    Assert-True (($windowsOnlyChecks | Where-Object { $_.explanation -notmatch 'Codespaces container' }).Count -eq 0) 'Codespaces Windows checks must explain that the host was not inspected.'
    Assert-True (($savedReport.checks | Where-Object { $_.checkName -eq 'Microsoft Graph Authentication module' }).explanation -match 'no Graph connection was attempted') 'The Graph prerequisite check must not authenticate.'

    $simulatedWindowsChecks = {
        param($checks)
        $checks.Add((New-FluxForgeAuditCheck -Name 'Windows management tooling availability' -Status PASS -Explanation 'Fixture tooling available.'))
        $checks.Add((New-FluxForgeAuditCheck -Name 'Windows Defender status' -Status WARNING -Explanation 'Fixture unavailable.'))
    }
    $windowsReport = Get-FluxForgeEnvironmentAudit -OutputDirectory (Join-Path $testRoot 'windows-report') -Environment $windows11 -WindowsCheckRunner $simulatedWindowsChecks
    $windowsSavedReport = Get-Content -LiteralPath $windowsReport.reportPath -Raw | ConvertFrom-Json
    Assert-True ($windowsSavedReport.operatingSystem.classification -eq 'Windows11' -and
        ($windowsSavedReport.checks | Where-Object { $_.checkName -eq 'Windows Defender status' }).status -eq 'WARNING' -and
        ($windowsSavedReport.checks | Where-Object { $_.checkName -eq 'Windows management tooling availability' }).status -eq 'PASS') 'Windows checks must be injectable for offline result/report tests.'

    $runnerFailureReported = $false
    try {
        Get-FluxForgeEnvironmentAudit -OutputDirectory (Join-Path $testRoot 'runner-failure') -Environment $windows10 -WindowsCheckRunner { throw 'fixture check failure' } | Out-Null
    }
    catch {
        $runnerFailureReported = $_.Exception.Message -match 'fixture check failure'
    }
    Assert-True $runnerFailureReported 'Unexpected platform-check failures must surface instead of returning success-shaped reports.'

    $blockedReportPath = Join-Path $testRoot 'not-a-directory'
    [System.IO.File]::WriteAllText($blockedReportPath, 'fixture')
    $reportWriteFailure = $false
    try {
        Get-FluxForgeEnvironmentAudit -OutputDirectory $blockedReportPath -Environment $linux | Out-Null
    }
    catch {
        $reportWriteFailure = $true
    }
    Assert-True $reportWriteFailure 'Report generation failures must surface as failures.'

    Write-Host "PASS: $script:testCount environment audit assertions passed."
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
