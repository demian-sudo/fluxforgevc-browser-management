# Policy schema and offline validation

## Schema version 1.0

The versioned schema is `config/schema/policy.schema.json`. It describes a policy document containing `schemaVersion` and a non-empty array of policies. Each policy declares:

- Policy ID and semantic version.
- Provider and platform, security objective, severity, and desired state.
- Enforcement mode, prerequisites, permissions, licensing, and capability requirements.
- Settings, exclusions, policy dependencies, and conflicts.
- Deployment ring and validation/verification steps.
- Rollback requirements, owner, review date, and illustrative status.

An `enforce` policy must include rollback information, keep `rollback.required` and `rollback.destructiveConfirmationRequired` true, and provide a non-whitespace rollback plan. Enforcement is not implemented and remains blocked by the script. Review dates must use `yyyy-MM-dd` and be real calendar dates. Cross-policy checks detect duplicate IDs, missing dependency references, declared conflicts, and different values for the same setting path when provider and platform match. An offline prerequisite is only considered supplied if explicitly passed to the tool; that does not independently verify the assertion.

## Run validation

From the repository root with PowerShell 7.4 or later:

```powershell
pwsh -NoProfile -File .\src\Invoke-FluxForgePolicyValidation.ps1
```

Optional local inputs:

```powershell
pwsh -NoProfile -File .\src\Invoke-FluxForgePolicyValidation.ps1 `
  -PolicyPath .\config\examples\policies.json `
  -CapabilityRegistryPath .\config\provider-capabilities.json `
  -AvailablePrerequisite windows-edition-and-management-source-verified `
  -Mode plan `
  -OutputDirectory .\reports\policy-audit
```

The tool writes sanitized JSON and Markdown reports. Structural, date, or cross-policy errors set `isValid` to false and `validationExitCode` to 1 in the report, then exit the process with status 1. Valid documents exit with status 0, including when evidence remains unverified. Unsupported, unknown, and unverified capability outcomes are distinct from schema validity. Reports use generated policy references rather than caller-provided IDs or free-text metadata and are ignored by Git.

`inventory`, `audit`, and `plan` are offline-only modes. `pilot`, `enforce`, and `rollback` fail before processing or report creation. No provider adapter is available in this release.

All provider examples are illustrative and do not assert a product feature, API, edition, license, tenant configuration, or control mapping.
