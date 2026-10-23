Set-StrictMode -Version Latest

$script:GraphApiRoot = 'https://graph.microsoft.com/v1.0'
$script:RequiredScopes = @{
    devices = @('DeviceManagementManagedDevices.Read.All')
    groups = @('Group.Read.All')
    groupMembers = @('GroupMember.Read.All')
    assignments = @('DeviceManagementConfiguration.Read.All')
}

function Get-FluxForgeGraphProviderConfiguration {
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        provider = 'microsoft-graph'
        apiRoot = $script:GraphApiRoot
        apiVersion = 'v1.0'
        authenticationMode = 'delegated-interactive'
        operationMode = 'read-only'
        status = 'NOT_VERIFIED'
        credentialsPersisted = $false
    }
}

function Get-FluxForgeGraphRequiredScopes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('devices', 'groups', 'groupMembers', 'assignments')]
        [string]$Operation
    )

    @($script:RequiredScopes[$Operation])
}

function Get-FluxForgeGraphResponseValue {
    param(
        [Parameter(Mandatory)]
        [object]$Response,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($Response -is [System.Collections.IDictionary]) {
        return ,$Response[$Name]
    }
    $property = $Response.PSObject.Properties[$Name]
    if ($property) {
        return ,$property.Value
    }
    return $null
}

function Get-FluxForgeGraphConnectionStatus {
    [CmdletBinding()]
    param(
        [scriptblock]$SdkModuleLocator,
        [scriptblock]$ContextProvider
    )

    $moduleLocator = if ($SdkModuleLocator) { $SdkModuleLocator } else { { Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Select-Object -First 1 } }
    $module = & $moduleLocator
    if (-not $module) {
        return [pscustomobject]@{
            status = 'NOT_VERIFIED'
            sdkAvailable = $false
            contextPresent = $false
            authenticated = $false
            scopes = @()
            reason = 'Microsoft.Graph.Authentication is not installed.'
        }
    }

    if ($ContextProvider) {
        $context = & $ContextProvider
    }
    else {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        $contextCommand = Get-Command Get-MgContext -ErrorAction SilentlyContinue
        if (-not $contextCommand) {
            return [pscustomobject]@{
                status = 'NOT_VERIFIED'
                sdkAvailable = $true
                contextPresent = $false
                authenticated = $false
                scopes = @()
                reason = 'The Graph SDK context command is unavailable.'
            }
        }
        $context = Get-MgContext -ErrorAction Stop
    }
    if (-not $context) {
        return [pscustomobject]@{
            status = 'NOT_VERIFIED'
            sdkAvailable = $true
            contextPresent = $false
            authenticated = $false
            scopes = @()
            reason = 'No Microsoft Graph session is present.'
        }
    }

    [pscustomobject]@{
        status = 'NOT_VERIFIED'
        sdkAvailable = $true
        contextPresent = $true
        authenticated = $false
        scopes = @($context.Scopes)
        reason = 'A local SDK context exists; authentication validity and provider reachability have not been verified by a Graph request.'
    }
}

function Connect-FluxForgeGraphReadOnly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('devices', 'groups', 'groupMembers', 'assignments')]
        [string[]]$Operation
    )

    $module = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Select-Object -First 1
    if (-not $module) {
        throw 'Microsoft.Graph.Authentication is required. Install the Microsoft Graph PowerShell SDK from an approved source, then retry.'
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $scopes = @($Operation | ForEach-Object { $script:RequiredScopes[$_] } | Select-Object -Unique)
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Connect-MgGraph is unavailable in Microsoft.Graph.Authentication.'
    }

    Connect-MgGraph -Scopes $scopes -ContextScope Process -NoWelcome -ErrorAction Stop
    Get-FluxForgeGraphConnectionStatus
}

function Disconnect-FluxForgeGraph {
    [CmdletBinding()]
    param()

    if (-not (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Disconnect-MgGraph is unavailable; no Graph session was disconnected.'
    }
    Disconnect-MgGraph -ErrorAction Stop
}

function Test-FluxForgeGraphPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('devices', 'groups', 'groupMembers', 'assignments')]
        [string]$Operation,
        [scriptblock]$ContextProvider
    )

    if ($ContextProvider) {
        $context = & $ContextProvider
    }
    else {
        $connection = Get-FluxForgeGraphConnectionStatus
        if (-not $connection.contextPresent) {
            return [pscustomobject]@{
                status = 'NOT_VERIFIED'
                operation = $Operation
                requiredScopes = @(Get-FluxForgeGraphRequiredScopes -Operation $Operation)
                grantedScopes = @()
                reason = 'Authentication is unavailable.'
            }
        }
        $context = [pscustomobject]@{ Scopes = $connection.scopes }
    }

    if (-not $context) {
        return [pscustomobject]@{
            status = 'NOT_VERIFIED'
            operation = $Operation
            requiredScopes = @(Get-FluxForgeGraphRequiredScopes -Operation $Operation)
            grantedScopes = @()
            reason = 'Authentication is unavailable.'
        }
    }

    $requiredScopes = @(Get-FluxForgeGraphRequiredScopes -Operation $Operation)
    $grantedScopes = @($context.Scopes | ForEach-Object { [string]$_ })
    $missingScopes = @($requiredScopes | Where-Object { $_ -notin $grantedScopes })
    [pscustomobject]@{
        status = if ($missingScopes.Count -eq 0) { 'GRANTED_IN_CONTEXT' } else { 'NOT_GRANTED' }
        operation = $Operation
        requiredScopes = $requiredScopes
        grantedScopes = @($grantedScopes | Where-Object { $_ -in $requiredScopes })
        reason = if ($missingScopes.Count -eq 0) {
            'Required delegated scopes are present in the local SDK context; a successful provider operation is not yet verified.'
        }
        else {
            'One or more required delegated scopes are absent from the local SDK context.'
        }
    }
}

function Invoke-FluxForgeGraphGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('devices', 'groups', 'groupMembers', 'assignments')]
        [string]$Operation,
        [Parameter(Mandatory)]
        [ValidatePattern('^/')]
        [string]$Path,
        [scriptblock]$RequestInvoker,
        [scriptblock]$ContextProvider
    )

    if ($Path -match '[\r\n]' -or $Path -match '(?i)^//|https?://|(^|/)\.\.(/|$)') {
        throw 'Only fixed Microsoft Graph v1.0 relative paths are accepted.'
    }

    $permission = Test-FluxForgeGraphPermission -Operation $Operation -ContextProvider $ContextProvider
    if ($permission.status -ne 'GRANTED_IN_CONTEXT') {
        throw "Microsoft Graph operation '$Operation' is blocked: $($permission.reason) Required delegated scope(s): $($permission.requiredScopes -join ', ')."
    }

    if ($RequestInvoker) {
        return & $RequestInvoker 'GET' ($script:GraphApiRoot + $Path)
    }

    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest is unavailable. Install Microsoft.Graph.Authentication and connect with the required delegated scopes.'
    }

    Invoke-MgGraphRequest -Method GET -Uri ($script:GraphApiRoot + $Path) -OutputType PSObject -ErrorAction Stop
}

function Get-FluxForgeGraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('devices', 'groups', 'groupMembers', 'assignments')]
        [string]$Operation,
        [Parameter(Mandatory)]
        [ValidatePattern('^/')]
        [string]$Path,
        [scriptblock]$RequestInvoker,
        [scriptblock]$ContextProvider
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextPath = $Path
    $pageCount = 0
    do {
        $response = Invoke-FluxForgeGraphGet -Operation $Operation -Path $nextPath -RequestInvoker $RequestInvoker -ContextProvider $ContextProvider
        $contextUrl = $null
        $value = $null
        if ($response) {
            $contextUrl = Get-FluxForgeGraphResponseValue -Response $response -Name '@odata.context'
            $value = Get-FluxForgeGraphResponseValue -Response $response -Name 'value'
        }
        if (-not $response -or [string]::IsNullOrWhiteSpace([string]$contextUrl) -or
            $null -eq $value -or $value -is [string] -or $value -isnot [System.Collections.IEnumerable]) {
            throw "Microsoft Graph operation '$Operation' returned an incomplete collection response."
        }

        foreach ($item in $value) {
            $items.Add($item)
        }
        $pageCount++

        $nextLink = [string](Get-FluxForgeGraphResponseValue -Response $response -Name '@odata.nextLink')
        if ($nextLink) {
            if (-not $nextLink.StartsWith($script:GraphApiRoot + '/', [System.StringComparison]::Ordinal) -or
                $nextLink -match '[\r\n]') {
                throw 'Microsoft Graph returned an invalid pagination link; collection completeness is unknown.'
            }
            $nextPath = $nextLink.Substring($script:GraphApiRoot.Length)
        }
        else {
            $nextPath = $null
        }
    } while ($nextPath)

    [pscustomobject]@{
        status = if ($RequestInvoker) { 'MOCKED' } else { 'VERIFIED' }
        complete = $true
        operation = $Operation
        count = $items.Count
        pageCount = $pageCount
        retrievedAt = [datetime]::UtcNow.ToString('o')
        providerContacted = -not [bool]$RequestInvoker
        evidenceSource = if ($RequestInvoker) { 'injected test transport; not provider evidence' } else { 'Microsoft Graph v1.0 GET' }
        items = @($items.ToArray())
    }
}

function Get-FluxForgeGraphManagedDevice {
    [CmdletBinding()]
    param(
        [scriptblock]$RequestInvoker,
        [scriptblock]$ContextProvider
    )

    Get-FluxForgeGraphCollection -Operation devices -Path '/deviceManagement/managedDevices?$select=id,operatingSystem,osVersion,managementState,azureADDeviceId&$top=100' -RequestInvoker $RequestInvoker -ContextProvider $ContextProvider
}

function Get-FluxForgeGraphManagedDeviceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string]$DeviceId,
        [scriptblock]$RequestInvoker,
        [scriptblock]$ContextProvider
    )

    $escapedDeviceId = [uri]::EscapeDataString($DeviceId)
    $response = Invoke-FluxForgeGraphGet -Operation devices -Path "/deviceManagement/managedDevices/${escapedDeviceId}?`$select=id,operatingSystem,osVersion,managementState,azureADDeviceId" -RequestInvoker $RequestInvoker -ContextProvider $ContextProvider
    if (-not $response -or -not (Get-FluxForgeGraphResponseValue -Response $response -Name 'id')) {
        throw 'Microsoft Graph returned no verified managed-device record.'
    }

    [pscustomobject]@{
        status = if ($RequestInvoker) { 'MOCKED' } else { 'VERIFIED' }
        providerReportedState = Get-FluxForgeGraphResponseValue -Response $response -Name 'managementState'
        endpointObservedState = 'NOT_VERIFIED'
        providerContacted = -not [bool]$RequestInvoker
        evidenceSource = if ($RequestInvoker) { 'injected test transport; not provider evidence' } else { 'Microsoft Graph v1.0 GET' }
        device = $response
    }
}

function Get-FluxForgeGraphGroup {
    [CmdletBinding()]
    param(
        [scriptblock]$RequestInvoker,
        [scriptblock]$ContextProvider
    )

    Get-FluxForgeGraphCollection -Operation groups -Path '/groups?$select=id,displayName,groupTypes,securityEnabled&$top=100' -RequestInvoker $RequestInvoker -ContextProvider $ContextProvider
}

function Get-FluxForgeGraphGroupDeviceMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string]$GroupId,
        [scriptblock]$RequestInvoker,
        [scriptblock]$ContextProvider
    )

    $escapedGroupId = [uri]::EscapeDataString($GroupId)
    Get-FluxForgeGraphCollection -Operation groupMembers -Path "/groups/$escapedGroupId/members/microsoft.graph.device?`$select=id,displayName&`$top=100" -RequestInvoker $RequestInvoker -ContextProvider $ContextProvider
}

function Get-FluxForgeGraphConfigurationAssignment {
    [CmdletBinding()]
    param(
        [scriptblock]$RequestInvoker,
        [scriptblock]$ContextProvider
    )

    $configurations = Get-FluxForgeGraphCollection -Operation assignments -Path '/deviceManagement/deviceConfigurations?$select=id,displayName,platforms&$top=100' -RequestInvoker $RequestInvoker -ContextProvider $ContextProvider
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($configuration in $configurations.items) {
        if (-not $configuration.id) {
            throw 'Microsoft Graph returned a configuration without an identifier; assignment completeness is unknown.'
        }
        $configurationId = [uri]::EscapeDataString([string]$configuration.id)
        $assignments = Get-FluxForgeGraphCollection -Operation assignments -Path "/deviceManagement/deviceConfigurations/$configurationId/assignments?`$top=100" -RequestInvoker $RequestInvoker -ContextProvider $ContextProvider
        $results.Add([pscustomobject]@{
            configuration = $configuration
            assignments = $assignments.items
            assignmentsComplete = $assignments.complete
        })
    }

    [pscustomobject]@{
        status = if ($RequestInvoker) { 'MOCKED' } else { 'VERIFIED' }
        complete = $true
        operation = 'assignments'
        count = $results.Count
        retrievedAt = [datetime]::UtcNow.ToString('o')
        providerContacted = -not [bool]$RequestInvoker
        evidenceSource = if ($RequestInvoker) { 'injected test transport; not provider evidence' } else { 'Microsoft Graph v1.0 GET' }
        items = @($results.ToArray())
    }
}

function Compare-FluxForgeInventoryToPolicyTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Policy,
        [Parameter(Mandatory)]
        [object]$Inventory,
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$LogicalToProviderGroupId,
        [System.Collections.IDictionary]$LogicalToProviderDeviceId = @{}
    )

    if ($Inventory.status -ne 'VERIFIED' -or -not $Inventory.complete -or
        $Inventory.items -isnot [System.Collections.IEnumerable]) {
        return [pscustomobject]@{
            status = 'NOT_VERIFIED'
            matchedCount = $null
            reason = 'Provider inventory is unavailable or incomplete; this result is not an empty tenant.'
        }
    }

    if ($Policy.target.kind -ne 'device') {
        return [pscustomobject]@{
            status = 'NOT_VERIFIED'
            matchedCount = $null
            reason = 'This inventory comparison applies only to device targets.'
        }
    }

    foreach ($device in $Inventory.items) {
        if (-not $device.id -or $device.operatingSystem -notin @($Policy.target.operatingSystems) -or
            $device.deviceType -notin @('windows', 'android') -or $null -eq $device.groupIds) {
            return [pscustomobject]@{
                status = 'NOT_VERIFIED'
                matchedCount = $null
                reason = 'Provider inventory is not completely normalized with device type, supported OS identifiers, and group membership.'
            }
        }
    }

    foreach ($logicalGroupId in @($Policy.target.groupIds)) {
        if (-not $LogicalToProviderGroupId.Contains($logicalGroupId)) {
            return [pscustomobject]@{
                status = 'NOT_VERIFIED'
                matchedCount = $null
                reason = 'A local logical group has no explicitly configured provider group mapping.'
            }
        }
    }

    foreach ($logicalGroupId in @($Policy.target.excludedGroupIds)) {
        if (-not $LogicalToProviderGroupId.Contains($logicalGroupId)) {
            return [pscustomobject]@{
                status = 'NOT_VERIFIED'
                matchedCount = $null
                reason = 'An excluded local logical group has no explicitly configured provider group mapping.'
            }
        }
    }

    foreach ($logicalDeviceId in @($Policy.target.deviceIds)) {
        if (-not $LogicalToProviderDeviceId.Contains($logicalDeviceId)) {
            return [pscustomobject]@{
                status = 'NOT_VERIFIED'
                matchedCount = $null
                reason = 'An opaque local device reference has no explicitly configured provider device mapping.'
            }
        }
    }

    $providerGroupIds = @($Policy.target.groupIds | ForEach-Object { [string]$LogicalToProviderGroupId[$_] })
    $providerDeviceIds = @($Policy.target.deviceIds | ForEach-Object { [string]$LogicalToProviderDeviceId[$_] })
    $matches = @($Inventory.items | Where-Object {
        $_.operatingSystem -in @($Policy.target.operatingSystems) -and
        $_.deviceType -in @($Policy.target.deviceTypes) -and
        (
            $_.id -in $providerDeviceIds -or
            @($_.groupIds | Where-Object { $_ -in $providerGroupIds }).Count -gt 0
        ) -and
        $_.id -notin @($Policy.target.excludedDeviceIds) -and
        @($_.groupIds | Where-Object { $_ -in @($Policy.target.excludedGroupIds | ForEach-Object { [string]$LogicalToProviderGroupId[$_] }) }).Count -eq 0
    })

    [pscustomobject]@{
        status = 'VERIFIED'
        matchedCount = $matches.Count
        reason = 'Compared against a complete provider inventory and explicit local-to-provider group mapping.'
    }
}

Export-ModuleMember -Function @(
    'Get-FluxForgeGraphProviderConfiguration',
    'Get-FluxForgeGraphRequiredScopes',
    'Get-FluxForgeGraphConnectionStatus',
    'Connect-FluxForgeGraphReadOnly',
    'Disconnect-FluxForgeGraph',
    'Test-FluxForgeGraphPermission',
    'Get-FluxForgeGraphManagedDevice',
    'Get-FluxForgeGraphManagedDeviceState',
    'Get-FluxForgeGraphGroup',
    'Get-FluxForgeGraphGroupDeviceMember',
    'Get-FluxForgeGraphConfigurationAssignment',
    'Compare-FluxForgeInventoryToPolicyTarget'
)
