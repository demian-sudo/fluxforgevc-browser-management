# Audit result states and security

## Common finding model

Every finding includes status, a generated policy reference, source, UTC timestamp, evidence description, confidence, verification status, and recommended next action. Policy results also distinguish desired state from observed state. Offline validation never reports a provider or endpoint observation; observed state remains `NOT_VERIFIED`.

| Status | Meaning |
|---|---|
| `PASS` | A local structural or static-register check passed. It is not proof of provider enforcement. |
| `FAIL` | Verified observed state contradicts desired state. The offline validator does not make this live-state determination. |
| `WARNING` | A non-fatal concern needs review. |
| `NOT_CONFIGURED` | A declared prerequisite was not supplied in the offline validation context. |
| `UNSUPPORTED` | The static local registry explicitly marks a required capability unsupported. |
| `NOT_VERIFIED` | Evidence is absent or capability support is unknown; neither pass nor fail. |
| `ERROR` | Local policy/schema or cross-policy validation failed. A future provider collection/API failure must also remain an error, not become a security failure. |

## Secret and evidence handling

Report generation uses an explicit allow-list: generated policy references, constrained provider/severity values, status, validation booleans, and fixed validator-authored finding text. It omits policy IDs, platform, owner, desired-state values, settings, prerequisites, permissions, capability names, and raw input. This reduces accidental disclosure but is not generic secret detection: it cannot identify every secret embedded in allowed fields, fixed environment metadata, or external handling. Review reports before sharing and keep credentials, tokens, private keys, recovery keys, and unnecessary personal/device data out of source files. `.gitignore` is a safeguard, not a substitute for review.

Schema-invalid or malformed policy files still produce a sanitized report when the output path is writable, then terminate with a nonzero process exit code. Real calendar-date validation supplements the JSON Schema format annotation.

The policy validator makes no network requests and has no credential flow. A separate opt-in Microsoft Graph adapter supports read-only requests, but no tenant authentication has been verified by repository tests. Policy deployment and rollback are not implemented.

## Local audit event log

Each run appends JSON Lines records to `reports/policy-audit/audit-events.jsonl`; `-AuditLogPath` can select another path. Normal offline runs record `validation_started` and `validation_completed`, including only the mode, outcome, validation boolean/error count, timestamp, and explicit `providerContacted: false` / `changesMade: false` values. Invalid results are logged as invalid. The `pilot`, `enforce`, and `rollback` modes record an `authorization_decision` of `denied` and a `deployment_attempt` of `blocked` before exiting without reading policy inputs or creating reports.

The log deliberately omits policy IDs, input paths, settings, users, devices, secrets, and credentials. A denied-operation record is not proof of an external authorization review. There is no authorization mechanism or policy mutation path in this version, so no successful authorization or policy-change event can occur or be logged. The JSONL file is local, append-oriented, and not tamper-evident or access-controlled; protect it as operational data and forward it to an approved protected audit system before relying on it for compliance.

## Tests

Run from the repository root:

```powershell
pwsh -NoProfile -File .\tests\Test-FluxForgePolicyFoundation.ps1
```

The test suite uses temporary local fixtures only. It verifies valid/invalid schema input, duplicate IDs, missing dependencies and prerequisites, declared and setting conflicts, unsupported capability reporting, enforcement rollback safeguards, JSON/Markdown reports, audit outcomes and redaction, malformed JSON, and blocked pilot/enforcement/rollback attempts. It does not require production credentials or contact providers.

## Policy lifecycle and recovery

The current workflow stops at offline validation and planning. A future deployment must gate each stage on reviewed prerequisites, current compatibility evidence, least-privilege authorization scoped to target/policy/ring/change window, and explicit approval. Pilot must precede broad enforcement, have bounded targets and success/stop criteria, and be independently authorized. Rollback must be validated and tested before any change; a policy's declarative rollback text is not an executable recovery mechanism.

If validation fails, an audit record cannot be written, targeting is uncertain, or a future operation's outcome is ambiguous, stop and do not retry a write blindly. Preserve audit evidence and the last known-good configuration; use the provider's approved recovery procedure with an authorized operator. This repository cannot perform or verify recovery.

## Offline targeting and conflict outcomes

Schema 1.1 can check declared Windows/Android device types, the supported OS identifier vocabulary, local group references and hierarchy, exclusions, and known device-family setting compatibility. `ERROR` means the local targeting declaration is malformed or internally incompatible; it does not mean a provider rejected an assignment. Contradictory values on a known overlapping group scope are errors for both generated policy references. Contradictions between compatible but unrelated groups are `NOT_VERIFIED`, because the validator cannot inspect membership. Equal values are accepted, differing setting paths are not assumed to conflict, and no policy wins automatically.

Every group assignment remains unverified for actual group existence, membership, enrollment, and effective assignment. Opaque device references are not queried and do not prove that a device exists or is targetable. The report intentionally uses generated references and omits raw identifiers and setting values. Do not place real device identifiers, user data, tenant IDs, or credentials in examples or audit logs.

## Limitations and prerequisites

- Capabilities are not discovered live; the static registry is not evidence of current provider support.
- No provider authentication, permission verification, device inventory, policy deployment, pilot, or rollback operation exists. No device enrollment, group membership, provider-side targeting, OS build compatibility, or remote management is verified.
- The example control intents are generic and must be reviewed against actual product features and licenses.
- Desired policy is not compared against provider-reported or endpoint-observed state.
- Google Workspace edition and GAM version/authentication/authorization are not verified. Neither are Chrome/Android management entitlements, Intune access, VPN/DNS products, or network-device capabilities.
- PowerShell 7.4 or later is required; CI uses a credential-free PowerShell job.
- CI pins `actions/checkout` to an immutable commit and disables persisted checkout credentials. The runner label `ubuntu-latest` and its preinstalled PowerShell runtime still change over time; review runner updates and action security advisories.

Verify provider APIs, tenant prerequisites, permissions, licensing, and documented capabilities before starting adapter work.
