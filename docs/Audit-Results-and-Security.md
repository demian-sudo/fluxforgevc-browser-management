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

The validator makes no network requests and has no credential flow. This repository contains no provider adapter, deployment, or rollback implementation.

## Tests

Run from the repository root:

```powershell
pwsh -NoProfile -File .\tests\Test-FluxForgePolicyFoundation.ps1
```

The test suite uses temporary local fixtures only. It verifies valid/invalid schema input, duplicate IDs, missing dependencies and prerequisites, declared and setting conflicts, unsupported capability reporting, enforcement rollback safeguards, JSON/Markdown reports, setting/secret omission, malformed JSON, and blocked enforcement. It does not require production credentials or contact providers.

## Limitations and prerequisites

- Capabilities are not discovered live; the static registry is not evidence of current provider support.
- No provider authentication, tenant/API read, policy deployment, pilot, or rollback operation exists.
- The example control intents are generic and must be reviewed against actual product features and licenses.
- Desired policy is not compared against provider-reported or endpoint-observed state.
- Google Workspace edition and GAM version/authentication/authorization are not verified. Neither are Chrome/Android management entitlements, Intune access, VPN/DNS products, or network-device capabilities.
- PowerShell 7.4 or later is required; CI uses a credential-free PowerShell job.
- CI pins `actions/checkout` to an immutable commit and disables persisted checkout credentials. The runner label `ubuntu-latest` and its preinstalled PowerShell runtime still change over time; review runner updates and action security advisories.

Verify provider APIs, tenant prerequisites, permissions, licensing, and documented capabilities before starting adapter work.
