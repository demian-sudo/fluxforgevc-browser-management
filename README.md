# FluxForgeVC Unified Enterprise Security & Policy Management

An offline-first foundation for describing and validating enterprise security policies. Policy validation does not connect to management providers or deploy configuration; a separate, explicitly invoked Microsoft Graph adapter supports read-only requests only.

## Current capabilities

- Versioned JSON policy schema and sanitized illustrative examples.
- Offline schema, dependency, device-targeting, assignment-conflict, prerequisite, and local capability validation.
- Sanitized JSON and Markdown reports with separate desired and observed states.
- Sanitized local JSON Lines audit events for validation outcomes and denied unavailable modes.
- Opt-in, read-only Microsoft Graph/Intune adapter for scoped delegated inventory and assignment inspection.
- Credential-free PowerShell tests and GitHub Actions validation.

The opt-in Graph adapter supports delegated read-only requests for selected inventory, groups, memberships, and device-configuration assignments, but no tenant authentication or operation has been verified in this repository. Policy deployment, pilot execution, and rollback are not implemented. No capability or license is inferred from an example policy.

## Requirements

- PowerShell 7.4 or later (`pwsh`).
- GitHub Actions runs the PowerShell runtime included in `ubuntu-latest`; its exact version follows the runner image and no setup action pins it. The workflow uses no production secrets.
- `actions/checkout` is pinned to an immutable commit. Review and update the pin deliberately when adopting security fixes.

## Validate the examples offline

From the repository root:

```powershell
pwsh -NoProfile -File .\src\Invoke-FluxForgePolicyValidation.ps1
```

The validator reads only local policy, schema, and capability registry files. It never authenticates, makes network requests, or writes provider configuration. It writes JSON and Markdown reports and appends sanitized audit events under `reports/policy-audit`; this directory is ignored by Git. Use `-AuditLogPath` to select another local event-log path. The report's `isValid` and `validationExitCode` indicate structural/cross-policy validation outcome. `NOT_VERIFIED` means there is no provider or endpoint observation; it is not a pass.

Select among the implemented offline modes:

```powershell
pwsh -NoProfile -File .\src\Invoke-FluxForgePolicyValidation.ps1 -Mode inventory
pwsh -NoProfile -File .\src\Invoke-FluxForgePolicyValidation.ps1 -Mode audit
pwsh -NoProfile -File .\src\Invoke-FluxForgePolicyValidation.ps1 -Mode plan
```

`pilot`, `enforce`, and `rollback` are recognized but blocked before processing inputs or writing reports. They are future modes, not available operations. A dry run is local-only and has no provider client.

The schema validates declared Windows/Android OS and logical group scope compatibility, but not real membership, enrollment, provider group identity, or remote management. See the [policy schema guide](docs/Policy-Schema-and-Validation.md) for conflict semantics and the [audit and safety guide](docs/Audit-Results-and-Security.md) for event-log limits, lifecycle prerequisites, and recovery guidance.

## Run tests

```powershell
pwsh -NoProfile -File .\tests\Test-FluxForgePolicyFoundation.ps1
```

Tests create temporary fixtures and reports, then remove them. They do not require production credentials or contact a provider.

## Audit the local environment

Run `pwsh -NoProfile -File ./scripts/audit/Test-FluxForgeEnvironment.ps1` to create a read-only JSON audit report. In Codespaces, results describe the Linux container—not the developer's physical Windows computer. For Windows Defender, firewall, Windows Update, and BitLocker checks, run PowerShell 7.4+ locally on the Windows device. The audit does not attempt elevation; administrator privileges may allow additional read-only information. See [Local environment audit](docs/Environment-Audit.md) for usage and limitations.

## Windows security audit and configuration preview

On the local Windows 10/11 computer, run `pwsh -NoProfile -File .\scripts\windows\Test-FluxForgeWindowsSecurity.ps1` for the default read-only audit. The Windows framework can preview supported firewall settings and has narrowly gated, backup-protected Apply/Restore operations; no device or tenant operation is implemented. Linux Codespaces cannot configure the physical Windows host. See [Windows security framework](docs/Windows-Security-Framework.md) for prerequisites, safeguards, recovery, and limitations.

## Policy inputs

- Schema: [config/schema/policy.schema.json](config/schema/policy.schema.json)
- Illustrative example policies: [config/examples/policies.json](config/examples/policies.json)
- Local capability reference: [config/provider-capabilities.json](config/provider-capabilities.json)

The examples cover Windows, Google Workspace, Chrome Enterprise, Android Enterprise, VPN, DNS, and network security. They are not provider-ready configurations. Unknown capabilities and unconfirmed prerequisites remain unverified or not configured.

## Documentation

- [Architecture and migration plan](docs/architecture/Policy-Foundation.md)
- [Schema and validation guide](docs/Policy-Schema-and-Validation.md)
- [Audit results and security handling](docs/Audit-Results-and-Security.md)
- [Microsoft Graph read-only adapter](docs/Microsoft-Graph-Read-Only.md)
- [Windows security framework](docs/Windows-Security-Framework.md)

## Security boundaries

Never add credentials, tokens, private keys, recovery material, or unnecessary personal/device data to policy files or source control. Review local reports before sharing. `.gitignore` excludes generated reports and common secret material; it is a safeguard, not a substitute for review.

No Google Workspace, Microsoft Graph, Intune, VPN, DNS, or network provider was contacted to build or test this foundation. Verify provider APIs, permissions, tenant prerequisites, and licensing before designing an adapter.
