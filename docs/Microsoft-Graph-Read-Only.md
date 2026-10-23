# Microsoft Graph and Intune read-only adapter

## Status and safety boundary

`src/FluxForge.MicrosoftGraph.ReadOnly.psm1` is an isolated, opt-in PowerShell adapter. Importing the module does not connect, authenticate, request consent, or contact a provider. Only an explicit call to `Connect-FluxForgeGraphReadOnly` starts interactive delegated authentication. Exported provider requests are fixed to Microsoft Graph v1.0 `GET`; write operations are not implemented or exported. This adapter cannot deploy, assign, update, delete, wipe, retire, or roll back policies or devices.

A local Graph SDK context is not proof that the access token remains valid or that a provider operation is available. The connection status is `NOT_VERIFIED` until a Graph request succeeds. Required scopes found in a local context are reported as `GRANTED_IN_CONTEXT`, not as proof of effective access. Provider errors are surfaced, and missing or incomplete collection responses throw instead of becoming empty inventory. Successful reads follow every validated Graph v1.0 pagination link before claiming completeness.

The current assignment reader is limited to Intune `deviceConfigurations` and their assignments. It does not read every Intune policy family, compliance state, endpoint telemetry, or effective configuration. No tenant has been connected or verified by repository tests.

## Runtime and module prerequisites

- PowerShell 7.4 or later.
- Microsoft Graph PowerShell SDK module `Microsoft.Graph.Authentication`, installed from an organization-approved PowerShell Gallery or internal repository.
- A delegated administrator account permitted by the organization to sign in and consent to the listed delegated scopes.
- Network access to the Microsoft identity platform and `https://graph.microsoft.com/v1.0`.

The adapter intentionally does not install modules automatically. Review package provenance and organization policies before installing the SDK. Do not put client secrets, passwords, access tokens, refresh tokens, tenant-specific identifiers, or device data in source files or command history.

## Delegated scopes

Only request scopes for the operations needed in a session. The `-Operation` argument to connect selects scopes:

| Operation | Delegated Graph permission | Purpose |
|---|---|---|
| `devices` | `DeviceManagementManagedDevices.Read.All` | Read Intune managed device inventory fields required for OS and management-state assessment. |
| `groups` | `Group.Read.All` | Read group metadata for explicit provider-group lookup. |
| `groupMembers` | `GroupMember.Read.All` | Read device members of a specified group. |
| `assignments` | `DeviceManagementConfiguration.Read.All` | Read Intune device configuration objects and their assignment records. |

These are read-only delegated scopes, but they can expose sensitive tenant/device/group information and some require administrator consent under Microsoft Entra policy. The adapter does not bypass consent. Confirm Microsoft Graph permission documentation and tenant consent requirements before interactive connection. Application permissions are not used. Do not request all scopes unless all respective operations are authorized and necessary.

## Safe interactive read-only session

Importing the adapter is offline:

```powershell
Import-Module ./src/FluxForge.MicrosoftGraph.ReadOnly.psm1
Get-FluxForgeGraphRequiredScopes -Operation devices
Get-FluxForgeGraphConnectionStatus
```

After a separate approval to query the tenant, sign in interactively for only the approved operation:

```powershell
Connect-FluxForgeGraphReadOnly -Operation devices
$inventory = Get-FluxForgeGraphManagedDevice
$inventory | Select-Object status, complete, count, pageCount, retrievedAt, providerContacted
```

For group lookup and membership, request only `groups` and/or `groupMembers`. For assignment review, request `assignments`. Inspect only the data required for the approved review; returned device and group fields are sensitive operational data. Disconnect when finished:

```powershell
Disconnect-FluxForgeGraph
```

Do not pass credentials or tokens to these functions. The adapter uses process-scoped Graph SDK context and does not persist tokens itself. The SDK may maintain authentication state according to its supported behavior; follow organizational token-handling and sign-out requirements.

## Provider inventory comparison boundary

`Compare-FluxForgeInventoryToPolicyTarget` accepts a complete, verified inventory, normalized device types and schema OS identifiers, group membership, and an explicit mapping from local logical group IDs to provider group IDs. It returns `NOT_VERIFIED` when inventory is absent/incomplete, records are not normalized, or any target group lacks a mapping. Mocked transport responses are marked `MOCKED` and cannot pass this comparison as provider evidence. A provider group name in a local policy is never treated as a real provider ID.

This comparison is only a boundary/helper; the Graph reader currently does not resolve logical group/device mappings or combine group-membership reads into normalized inventory. Until a separately reviewed inventory normalization and mapping workflow is implemented, inventory-to-policy comparison remains unverified. The per-device state function reports provider-returned `managementState` separately from endpoint observation, which remains `NOT_VERIFIED`.

## Offline tests

Run:

```powershell
pwsh -NoProfile -File ./tests/Test-FluxForgePolicyFoundation.ps1
```

The Graph tests use injected request and context functions. They do not import the Graph SDK, request consent, use credentials, or make network calls. Fixture data is explicitly marked mocked and is not provider evidence.

## Limitations and next steps

- Authentication status and delegated scopes are read from a local SDK context; only a successful Graph `GET` confirms that a particular request worked at that time.
- Microsoft Graph permissions, endpoint availability, supported filters, throttling, tenant consent, and Intune licensing must be confirmed in the target environment.
- Group lookup and membership can reveal sensitive data and must have an approved business purpose and scoped handling.
- Configuration assignment reads cover only the classic device configuration endpoint implemented here; they do not establish effective device state.
- No policy enforcement, pilot, rollback, compliance change, tenant configuration, or device operation exists in this adapter.
- Unknown, partial, stale, or failed provider evidence must remain `NOT_VERIFIED` or a surfaced error; it must never authorize enforcement.

The recommended next step is a separately approved read-only test against a non-production or otherwise authorized tenant, followed by review of actual consented scopes, returned-field minimization, completeness, and provider errors. Do not proceed to deployment until that review and an independent authorization design are complete.
