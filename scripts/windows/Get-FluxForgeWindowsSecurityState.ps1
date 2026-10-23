[CmdletBinding()]
param(
    [scriptblock]$StateReader,
    [scriptblock]$EnvironmentProvider,
    [scriptblock]$AdministratorProvider
)

$modulePath = Join-Path $PSScriptRoot 'FluxForge.WindowsSecurity.psm1'
Import-Module $modulePath -Force
Get-FluxForgeWindowsSecurityState -StateReader $StateReader -EnvironmentProvider $EnvironmentProvider -AdministratorProvider $AdministratorProvider
