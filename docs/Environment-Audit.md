# Local environment audit

`scripts/audit/Test-FluxForgeEnvironment.ps1` performs read-only checks and writes a structured JSON report. It does not change security settings, install software, enroll devices, authenticate to Microsoft Graph, or modify tenant/device state.

## GitHub Codespaces

From the repository root:

```powershell
pwsh -NoProfile -File ./scripts/audit/Test-FluxForgeEnvironment.ps1
```

The report classifies Codespaces as `LinuxCodespaces`. Windows Defender, Windows Firewall, Windows Update, and BitLocker checks are marked `NOT_VERIFIED` because the Linux container cannot inspect the host computer. These results describe the Codespaces container, not the developer's physical Windows device.

To choose an output directory:

```powershell
pwsh -NoProfile -File ./scripts/audit/Test-FluxForgeEnvironment.ps1 -OutputDirectory ./reports/environment-audit
```

## Local Windows computer

Run the same command in PowerShell 7.4 or later on the Windows computer being assessed:

```powershell
pwsh -NoProfile -File .\scripts\audit\Test-FluxForgeEnvironment.ps1
```

The script classifies supported Windows 10/11 builds, reads available Defender, firewall, Windows Update service, and BitLocker information, and reports installed read-only management commands. It does not attempt to elevate. Without administrator privileges, protected data may be unavailable; the affected result remains `NOT_VERIFIED` with remediation guidance.

With administrator privileges, run PowerShell as administrator only when authorized by your organization, then execute the same audit command. Elevation may allow additional read-only status checks, but the script still does not change settings. It never reads BitLocker recovery keys, passwords, tokens, or Graph credentials.

Specify another report directory with `-OutputDirectory`:

```powershell
pwsh -NoProfile -File .\scripts\audit\Test-FluxForgeEnvironment.ps1 -OutputDirectory "$env:TEMP\FluxForge-Environment-Audit"
```

## Report and statuses

The generated JSON includes a UTC timestamp, OS classification/scope, read-only boundary indicators, and checks with `PASS`, `FAIL`, `WARNING`, or `NOT_VERIFIED` status, explanation, and optional remediation. An unavailable check is not represented as a pass. `NOT_VERIFIED` means the required evidence was not available to this audit; it is not a claim that a control is disabled or enabled.

The default output is `reports/environment-audit`, which is ignored by Git. Review reports before sharing them. Device inventory, usernames, tenant identifiers, and authentication material are not collected.

## Offline tests

From the repository root:

```powershell
pwsh -NoProfile -File ./tests/Test-FluxForgeEnvironmentAudit.ps1
pwsh -NoProfile -File ./tests/Test-FluxForgePolicyFoundation.ps1
pwsh -NoProfile -File ./tests/Test-FluxForgeWindowsSecurity.ps1
```

Tests use injected platform/check fixtures and do not modify Windows settings or connect to Microsoft Graph.
