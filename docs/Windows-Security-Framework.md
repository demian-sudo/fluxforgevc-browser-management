# Windows security configuration framework

The framework in `scripts/windows/` is a local Windows-only configuration tool. Its default mode is **Audit**. Audit, Plan, and Verify are read-only. No Android management, Microsoft Graph connection, tenant operation, enrollment, or remote device deployment is implemented.

## Requirements and supported settings

- Windows 10 or Windows 11, verified from local operating-system information.
- PowerShell 7.4 or later and the Windows commands/modules needed for each individual check.
- Administrator privileges for Apply and Restore. The scripts never attempt elevation.
- Run commands only on the Windows computer being inspected or changed. Linux-based Codespaces report the container as unsupported and cannot inspect or configure the physical Windows host.

The audit reads Windows Defender status, Windows Firewall profiles, Windows Update service visibility, PowerShell version/language/execution policy, Edge and Chrome policy-key presence, and BitLocker volume status. An unavailable command, permission, or state is `NOT_VERIFIED`; it is not inferred to be enabled or disabled. The administrator check reports `PASS` (verified elevated), `FAIL` (verified not elevated), or `NOT_VERIFIED`. A `PASS` setting-check status indicates that state was retrieved, not that the retrieved setting meets an organizational security baseline. BitLocker recovery keys are never read.

The supported policy format is described by `config/schema/windows-security-policy.schema.json`; its example is `config/examples/windows-security-policy.json`. The only setting currently supported for Apply and Restore is enabling selected `Domain`, `Private`, and `Public` Windows Firewall profiles. For this setting, the framework:

1. Validates the local JSON policy and reads the current profile state.
2. Displays the exact profile values in Plan/Apply previews.
3. Requires administrator privileges and the case-sensitive confirmation `APPLY FirewallProfile.Enabled=true`.
4. Writes a checksummed backup containing the previous profile values and a sanitized JSON Lines audit event before changing firewall settings.
5. Re-reads state and reports failure if the intended values cannot be verified.
6. Allows Restore only from an integrity-checked backup for the same supported Windows classification, with administrator privileges and exact confirmation `RESTORE <backupId>`.

Other audit-visible settings are not writable. Unsupported settings, invalid profiles, unavailable state, absent prerequisites, or failed authorization are rejected; the framework does not choose a fallback or silently skip controls. If a provider command partially changes state before failing, the script reports failure and leaves recovery to the operator using the generated backup; it does not claim or attempt automatic rollback.

## Run the audit

From the repository root on the local Windows computer, with or without administrator privileges:

```powershell
pwsh -NoProfile -File .\scripts\windows\Test-FluxForgeWindowsSecurity.ps1
```

Audit is the default and makes no system changes. Findings that require elevated access can remain `NOT_VERIFIED` when run without administrator privileges. The default JSON report and audit log are written under `reports/windows-security/`, which is ignored by Git.

To select the report directory:

```powershell
pwsh -NoProfile -File .\scripts\windows\Test-FluxForgeWindowsSecurity.ps1 -Mode Audit -OutputDirectory "$env:TEMP\FluxForge-Windows-Security"
```

## Preview, apply, verify, and restore

Use the illustrative policy at `config/examples/windows-security-policy.json`, or prepare a reviewed local policy with the same schema:

```powershell
pwsh -NoProfile -File .\scripts\windows\Test-FluxForgeWindowsSecurity.ps1 -Mode Plan
pwsh -NoProfile -File .\scripts\windows\Test-FluxForgeWindowsSecurity.ps1 -Mode Apply -Confirmation 'APPLY FirewallProfile.Enabled=true'
pwsh -NoProfile -File .\scripts\windows\Test-FluxForgeWindowsSecurity.ps1 -Mode Verify
```

Apply prints the profiles, prior values, and intended values before proceeding. The explicit confirmation is an authorization gate, not a substitute for organizational change approval. Review the policy, preview, authorization, backup destination, and impact before supplying it. Apply never runs in tests or from the Codespaces/Linux environment.

Apply returns the backup path. Preserve it securely and do not commit or share it casually. Restore the prior values with the backup-specific confirmation shown by the backup ID:

```powershell
pwsh -NoProfile -File .\scripts\windows\Test-FluxForgeWindowsSecurity.ps1 -Mode Restore -BackupPath .\reports\windows-security\backups\<backup-file>.json -Confirmation 'RESTORE <backupId>'
```

Restore validates the backup checksum and setting/profile structure before invoking a writer, then verifies restored state. Keep a separate copy of the backup in an organization-approved recovery location before changes. A checksum detects accidental or unauthorized modification; it is not a signature and does not prove who created the file. If the backup is unavailable or invalid, Restore fails closed.

The direct scripts `Get-FluxForgeWindowsSecurityState.ps1`, `Set-FluxForgeWindowsSecurityPolicy.ps1`, and `Restore-FluxForgeWindowsSecurityPolicy.ps1` expose state retrieval and narrowly gated operations for automation. Prefer the `Test-FluxForgeWindowsSecurity.ps1` entry point for normal use.

## Audit records and privacy

The local JSON Lines log records plan creation, denied Apply/Restore authorization, and apply/restore start, completion, or failure, including the setting and whether changes were made. It deliberately omits usernames, device identifiers, credentials, tokens, and raw provider output. Protect reports, logs, and backups according to local policy; the audit log is not tamper-proof or centrally collected.

## Offline tests and limitations

Run all offline suites from the repository root:

```powershell
pwsh -NoProfile -File ./tests/Test-FluxForgePolicyFoundation.ps1
pwsh -NoProfile -File ./tests/Test-FluxForgeEnvironmentAudit.ps1
pwsh -NoProfile -File ./tests/Test-FluxForgeWindowsSecurity.ps1
```

The Windows framework suite injects mock operating-system state, authorization, and setting writers. It does not invoke Windows management cmdlets or modify a computer. Tests on Linux/Codespaces cannot verify Windows cmdlet behavior, administrator rights, actual policy application, or organization-specific firewall configuration. Before any authorized local change, validate the reviewed policy and recovery plan with the responsible Windows administrator.
