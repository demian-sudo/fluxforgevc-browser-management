[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PolicyPath,
    [Parameter(Mandatory)][string]$BackupDirectory,
    [Parameter(Mandatory)][string]$AuditLogPath,
    [string]$Confirmation = '',
    [scriptblock]$StateReader,
    [scriptblock]$EnvironmentProvider,
    [scriptblock]$AdministratorProvider,
    [scriptblock]$Setter
)

$modulePath = Join-Path $PSScriptRoot 'FluxForge.WindowsSecurity.psm1'
Import-Module $modulePath -Force
Set-FluxForgeWindowsSecurityPolicy @PSBoundParameters
