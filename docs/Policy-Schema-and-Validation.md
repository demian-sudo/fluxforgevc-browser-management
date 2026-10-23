# Policy schema and offline validation

## Schema version 1.1

The versioned schema is `config/schema/policy.schema.json`. It describes a policy document containing `schemaVersion`, a `deviceGroups` catalog, and a non-empty array of policies. Each policy declares:

- Policy ID and semantic version.
- Provider, target, platform, security objective, severity, and desired state.
- Enforcement mode, prerequisites, permissions, licensing, and capability requirements.
- Settings, exclusions, policy dependencies, and conflicts.
- Deployment ring and validation/verification steps.
- Rollback requirements, owner, review date, and illustrative status.

An `enforce` policy must include rollback information, keep `rollback.required` and `rollback.destructiveConfirmationRequired` true, and provide a non-whitespace rollback plan. Enforcement is not implemented and remains blocked by the script. Review dates must use `yyyy-MM-dd` and be real calendar dates. An offline prerequisite is only considered supplied if explicitly passed to the tool; that does not independently verify the assertion.

Dependency validation builds a directed graph from references to policies present in the document and uses an iterative strongly connected component traversal. Every policy in a multi-policy cyclic component receives `ERROR` status and exactly one sanitized circular-dependency finding, including when multiple cycles overlap. Acyclic policies are not marked cyclic. Missing references are reported separately because their targets are not graph vertices; self-references receive the existing self-dependency finding and are not reported as multi-policy cycles. Any of these errors sets the affected policy's status to `ERROR`.

## Device targeting and assignment

Each policy requires a `target`. Use `kind: "device"` for Windows/Android device assignments and `kind: "provider"` for organization/tenant-scoped policies that are not device assignments. Device targets declare `deviceTypes`, supported `operatingSystems`, one or more `groupIds` or explicitly formatted opaque `deviceIds`, and optional `excludedGroupIds`/`excludedDeviceIds`. Supported OS identifiers are `windows-10`, `windows-11`, and `android-10` through `android-15`. Known Windows and Android settings are checked against their device family; unknown setting semantics remain provider-specific and unverified.

The top-level `deviceGroups` catalog declares unique logical `groupId`, `deviceType`, `operatingSystems`, and optional `parentGroupIds`. Parent groups represent hierarchical scopes. Group references must resolve, group OS/device-type constraints must be compatible, and parent cycles are rejected. A child group must remain within its parent's declared scope. These are local assignment declarations, not provider group IDs or evidence of real group membership. Actual membership, enrollment, and effective assignments remain `NOT_VERIFIED`.

Conflict analysis is deterministic. It compares policies for the same provider and same setting path; different paths are not assumed to conflict. A shared group or ancestor/descendant relationship is treated as overlapping, subject to declared exclusions. Disjoint device-type or OS selectors do not conflict. Different compatible groups with no declared hierarchy have unknown membership, so contradictory values produce `NOT_VERIFIED` findings instead of a false claim of overlap or disjointness. Same explicit opaque device references overlap unless excluded. Equal values are compatible; no winner is selected. Findings identify each affected policy with generated, sanitized report references rather than raw policy IDs.

The validator cannot verify whether a provider group exists, contains devices, or is actually disjoint from another group. Explicit device identifiers must use the documented opaque reference syntax, but are not authenticated, inventoried, or guaranteed targetable by a provider. Do not put real device identifiers into source control.

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

The tool writes sanitized JSON and Markdown reports and appends sanitized JSON Lines audit events to `reports/policy-audit/audit-events.jsonl`. Use `-AuditLogPath` to select another local path. Structural, date, or cross-policy errors set `isValid` to false and `validationExitCode` to 1 in the report, then exit the process with status 1. Valid documents exit with status 0, including when evidence remains unverified. Unsupported, unknown, and unverified capability outcomes are distinct from schema validity. Reports and audit events use generated references or fixed event metadata rather than caller-provided IDs, input paths, or free-text metadata and are ignored by Git.

`inventory`, `audit`, and `plan` are offline-only modes. `pilot`, `enforce`, and `rollback` are rejected before policy processing or report creation; the audit log records a denied authorization decision and blocked operation. Supplying `-AvailablePrerequisite` is only an operator-provided assertion for offline assessment, not independent evidence or authorization. There is no authorization workflow or provider adapter in this release; these modes remain unavailable regardless of supplied prerequisites.

All provider examples are illustrative and do not assert a product feature, API, edition, license, tenant configuration, or control mapping.

## Targeting, lifecycle, and recovery limits

`platform` and provider identifiers are descriptive labels. Schema targeting checks a declared OS vocabulary, device-family compatibility, logical group references, and declared scope overlap; it does not check Windows build compatibility, Android management mode, enrollment, group membership, provider group identity, or effective targeting. Do not treat these offline checks as proof that any device is enrolled or targetable.

## Provider integration boundary

`config/provider-capabilities.json` is local reference metadata only. It keeps capability declarations separate from authentication, permission verification, device inventory, group membership, explicit-device targeting, and deployment execution. All six integration surfaces are explicitly `not-implemented`; no token is requested or persisted, and no provider is contacted. Missing or unknown evidence remains `NOT_VERIFIED`. Microsoft Intune and Microsoft Graph readiness must be established with a separately reviewed, read-only adapter before any deployment design.

The intended future lifecycle is offline validation, prerequisite and capability review, a separately authorized bounded pilot, evidence-based review, then separately authorized broader enforcement. No pilot-first or enforcement action is implemented today. Before any future write operation, establish current provider/API compatibility, enrollment and target-group scope, least-privilege authorization, licensing, a tested rollback path, and a distinct approval. On an invalid result or any uncertainty, stop and retain the prior known-good provider configuration. This validator does not change state and cannot execute recovery.
