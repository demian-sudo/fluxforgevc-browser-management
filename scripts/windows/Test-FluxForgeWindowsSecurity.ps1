[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Plan', 'Apply', 'Verify', 'Restore')]
    [string]$Mode = 'Audit',
    [string]$PolicyPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../config/examples/windows-security-policy.json')),
    [string]$BackupPath,
    [string]$Confirmation,
    [string]$OutputDirectory,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'FluxForge.WindowsSecurity.psm1'
Import-Module $modulePath -Force

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $OutputDirectory = Join-Path $repositoryRoot 'reports/windows-security'
}
$auditLogPath = Join-Path $OutputDirectory 'audit-events.jsonl'
$report = $null

try {
    switch ($Mode) {
        'Audit' {
            $report = Get-FluxForgeWindowsSecurityState
            $report | Add-Member -NotePropertyName mode -NotePropertyValue 'Audit'
            $report | Add-Member -NotePropertyName changesMade -NotePropertyValue $false
        }
        'Plan' {
            $report = Get-FluxForgeWindowsPlan -PolicyPath $PolicyPath
            Write-FluxForgeWindowsAuditEvent -Path $auditLogPath -EventType plan_created -Outcome planned -Setting 'FirewallProfile.Enabled'
        }
        'Apply' {
            $report = Set-FluxForgeWindowsSecurityPolicy -PolicyPath $PolicyPath -BackupDirectory (Join-Path $OutputDirectory 'backups') -AuditLogPath $auditLogPath -Confirmation ([string]$Confirmation)
        }
        'Verify' {
            $policy = Get-FluxForgeWindowsPolicy -PolicyPath $PolicyPath
            $state = Get-FluxForgeWindowsSecurityState
            $firewallCheck = $state.checks | Where-Object checkName -eq 'Windows Firewall profiles' | Select-Object -First 1
            $results = [System.Collections.Generic.List[object]]::new()
            foreach ($setting in $policy.settings) {
                foreach ($profileName in $setting.profiles) {
                    $profile = @($firewallCheck.value) | Where-Object name -eq $profileName | Select-Object -First 1
                    $status = if ($firewallCheck.status -ne 'PASS' -or -not $profile) {
                        'NOT_VERIFIED'
                    }
                    elseif ([bool]$profile.enabled -eq [bool]$setting.value) {
                        'PASS'
                    }
                    else {
                        'FAIL'
                    }
                    $results.Add([pscustomobject]@{
                        setting = $setting.name
                        profile = $profileName
                        status = $status
                    })
                }
            }
            $report = [pscustomobject]@{
                mode = 'Verify'
                operatingSystem = $state.operatingSystem
                results = @($results.ToArray())
                changesMade = $false
            }
        }
        'Restore' {
            if ([string]::IsNullOrWhiteSpace($BackupPath)) { throw 'Restore requires -BackupPath to a verified backup.' }
            $report = Restore-FluxForgeWindowsSecurityPolicy -BackupPath $BackupPath -AuditLogPath $auditLogPath -Confirmation ([string]$Confirmation)
        }
    }

    if ($Mode -in @('Audit', 'Plan', 'Verify')) {
        $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
        $reportPath = Join-Path $OutputDirectory "FluxForge-Windows-Security-$Mode-$([datetime]::UtcNow.ToString('yyyyMMdd-HHmmssfff')).json"
        [System.IO.File]::WriteAllText($reportPath, (ConvertTo-Json -InputObject $report -Depth 20), [System.Text.UTF8Encoding]::new($false))
        $report | Add-Member -NotePropertyName reportPath -NotePropertyValue $reportPath
    }
    if ($Json) {
        $report | ConvertTo-Json -Depth 20
    }
    else {
        $report | Format-List
    }
}
catch {
    Write-Error "Windows security $Mode failed: $($_.Exception.Message)"
    exit 1
}
