# Policy foundation architecture

## Implemented boundary

`src/Invoke-FluxForgePolicyValidation.ps1` reads local policy JSON, a local JSON Schema, and a local capability registry. It makes no network calls, loads no provider modules, authenticates nowhere, and changes no provider or endpoint configuration. JSON and Markdown reports are created locally under ignored `reports/policy-audit`.

This repository began empty. It contains no pre-existing provider integrations or workflows that this foundation replaces. Provider adapters are not implemented.

## Module boundaries

The shared versioned policy document is provider-neutral metadata. Provider names are identifiers for future independent adapters, not a claim of universal APIs. Planned adapter boundaries are Windows endpoints, Microsoft Intune, Google Workspace, Chrome Enterprise, Android Enterprise, VPN, DNS filtering, and network security. Each future adapter must own its documented API surface, authentication, least-privilege permissions, capability/licensing checks, provider-specific errors, and evidence provenance.

The current capability registry is static local reference data and is not live support discovery. The isolated Microsoft Graph module implements opt-in read-only requests, but has not been authenticated against a tenant. Examples are explicitly illustrative.

## Targeting and assignment model

Policy schema version 1.1 requires every policy to declare either a device target or a provider/tenant scope. Device targets select Windows and/or Android device families, an explicit OS vocabulary, local logical group references and, where syntax permits, opaque device references. Exclusions are expressed separately for groups and device references. The document-level device group catalog supports parent/child scope declarations and rejects missing references, incompatible OS constraints, and hierarchy cycles.

These group IDs are local names, not Microsoft Entra/Intune identifiers. The model does not include live membership data. Equal groups and parent/child relationships are treated as overlapping; unrelated groups with compatible OS/device constraints remain ambiguous. Declared exclusions are applied to known hierarchy overlap. Different device types or disjoint OS sets are treated as disjoint. Conflict checks compare the same provider and setting path only; contradictory settings on known overlapping scopes are errors, compatible values are accepted, and unknown overlap is reported as `NOT_VERIFIED`. No policy wins automatically.

Device IDs use an opaque syntax only and are not real or invented inventory entries in examples. Their existence, enrollment, membership, provider support, and targetability cannot be verified offline.

## Provider adapter contract

The local capability registry separates four future adapter responsibilities: authentication status, permission verification, device inventory retrieval, and deployment execution. All are `not-implemented` in this foundation. Static capability declarations do not authenticate a caller or verify tenant permissions.

A future Microsoft Graph/Intune adapter should expose separate operations with typed, sanitized results:

| Operation | Required result | Current status |
|---|---|---|
| Authentication check | `status`, `checkedAt`, `providerContacted`; never return credential material | Not implemented |
| Permission verification | `status`, verified permission names, evidence source, timestamp | Not implemented |
| Device inventory read | `status`, scoped opaque references, evidence source, timestamp | Not implemented |
| Group membership / explicit targeting check | `status`, opaque scope references, evidence source, timestamp | Not implemented |
| Policy deployment | `status`, approval reference, target scope, change reference, provider response status | Not implemented |

Unavailable or inconclusive reads must return `NOT_VERIFIED`; errors must remain errors and never be converted to success. These are interface requirements, not callable methods or evidence of connectivity. Future Graph/Intune work should begin with an independently reviewed read-only adapter. Credentials must be obtained through an approved secret broker and never written to policy, reports, or audit files. Deployment must remain a separate component gated by validation, explicit authorization and confirmation, scoped targets, verified provider state, and tested rollback.

## Policy lifecycle and state model

The intended lifecycle is: desired policy → schema validation → prerequisite/capability assessment → offline plan → separately approved pilot → provider-reported deployed state → endpoint verification → authorized rollback when necessary.

This release implements only local validation and assessment. Finding states are `PASS`, `FAIL`, `WARNING`, `NOT_CONFIGURED`, `UNSUPPORTED`, `NOT_VERIFIED`, and `ERROR`. `NOT_VERIFIED` never means compliant. Missing prerequisites are `NOT_CONFIGURED`; absent capability evidence is `NOT_VERIFIED`; static explicit unsupported entries are `UNSUPPORTED`. An API error in a future adapter must be reported as a collection `ERROR`, not converted into a security `FAIL`.

## Authentication and authorization boundaries

The offline validator has no authentication mechanism and requires no credentials. It does not request permissions or inspect environment credentials. A future adapter must request only verified, least-privilege permissions for its intended operation. Provider licensing, tenant edition, API enablement, and granted access must not be inferred from sample files.

## Reports and evidence

The JSON report is machine-readable; Markdown provides a concise review view. Findings identify source, UTC timestamp, evidence description, confidence, verification status, and next action. Policy output separately reports whether desired state is specified and whether observed state was verified. Desired setting values and raw input are omitted from reports. Parser detail is generic to avoid accidental disclosure.

Treat source policies and reports as operational information. Keep credentials, tokens, private keys, recovery data, and unnecessary personal/device identifiers out of the repository. Review reports before sharing.

## Capability detection

Only the local static capability register is read. No provider endpoint is contacted. Entries should be added only with a documented evidence source and review date, and must still be confirmed against the actual tenant edition, licensing, permissions, and deployed product version before implementation.

## Modes, approvals, and rollback

`inventory`, `audit`, and `plan` currently run only the offline validator. `pilot`, `enforce`, and `rollback` are explicit future modes and are blocked before reading input or writing reports. There are no production write operations.

A future deployment feature requires an auditable approval scoped to provider, policy IDs, target group, deployment ring, change window, and expiry. Pilot operation must be bounded and define verification criteria. Enforcement must require explicit approval and revalidate capabilities and plan inputs. Destructive operations require a separate confirmation. Rollback must have a reviewed provider-specific recovery plan; declarative rollback text is not an executable rollback mechanism.

## Migration and next steps

1. Review and validate shared policy documents offline.
2. Verify Google Workspace/GAM version, supported authentication, API prerequisites, permissions, and license before designing read-only inventory.
3. Add one independent, read-only adapter at a time with provider-specific tests and error semantics.
4. Preserve the boundary between desired policy, provider-reported state, and endpoint evidence.
5. Implement planning and approval before considering writes; require a separately reviewed phase for production deployment and rollback.

No production provider was contacted in this phase.
