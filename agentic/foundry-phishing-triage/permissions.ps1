param(
  # Object ID of the Function managed identity. Default: FUNCTION_PRINCIPAL_ID from deployment.env.
  [string]$FunctionPrincipalId
)
$ErrorActionPreference = 'Stop'
# Without -FunctionPrincipalId, take the Function managed identity from deployment.env (written by deploy.ps1).
if (-not $FunctionPrincipalId) {
  $envFile = Join-Path $PSScriptRoot 'deployment.env'
  if (Test-Path -LiteralPath $envFile) {
    $line = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*FUNCTION_PRINCIPAL_ID=(.+)$' } | Select-Object -First 1
    if ($line -match '^\s*FUNCTION_PRINCIPAL_ID=(.+)$') { $FunctionPrincipalId = $Matches[1].Trim() }
  }
  if (-not $FunctionPrincipalId) { throw 'No -FunctionPrincipalId given and no FUNCTION_PRINCIPAL_ID in deployment.env - run deploy.ps1 first or pass the object ID.' }
  Write-Host "Function managed identity from deployment.env: $FunctionPrincipalId" -ForegroundColor DarkGray
}
# Grants the Function managed identity its Defender XDR and Graph application roles.
# Uses the Azure CLI login (az rest) instead of the Microsoft.Graph PowerShell modules.
# Run as an Entra administrator who may assign app roles (e.g. Privileged Role Administrator).
# These roles cover the Function -> Graph leg. The Foundry -> Function leg uses a shared key in this demo;
# for production use Entra ID there too (see README 'Production: use Entra ID authentication').
# This intentionally does not grant Graph Mail.Read. Use reporting-mailbox-access.ps1
# for a separately approved Exchange Application RBAC scope limited to one mailbox.

$graph = 'https://graph.microsoft.com/v1.0'
function Invoke-Graph([string]$Method, [string]$Url, $Body) {
  $azArgs = @('rest', '--method', $Method, '--url', $Url, '--output', 'json', '--only-show-errors')
  $tmp = $null
  if ($Body) {
    # Pass the body via file to avoid shell quoting issues.
    $tmp = New-TemporaryFile
    $Body | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $tmp -Encoding utf8
    $azArgs += @('--headers', 'Content-Type=application/json', '--body', "@$tmp")
  }
  try {
    $out = az @azArgs
    if ($LASTEXITCODE -ne 0) { throw "Graph $Method $Url failed." }
    if ($out) { ($out -join "`n") | ConvertFrom-Json } else { $null }
  } finally {
    if ($tmp) { Remove-Item -LiteralPath $tmp -Force }
  }
}

$tenantId = az account show --query tenantId --output tsv --only-show-errors
$account = az account show --query user.name --output tsv --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'Not logged in to Azure CLI. Run az login first.' }
Write-Host "Using Azure CLI login " -NoNewline; Write-Host $account -ForegroundColor Cyan -NoNewline
Write-Host " (tenant " -NoNewline; Write-Host $tenantId -ForegroundColor Cyan -NoNewline; Write-Host ")"
$assigned = 0; $skipped = 0

# Defender XDR data is read only through Microsoft Graph security APIs (runHuntingQuery, incidents).
# The legacy Microsoft Threat Protection API (api.security.microsoft.com, appId 8ee8fdad-...) is not used;
# any app roles on it are removed below to keep the identity least-privileged.
$targets = @(
  @{ AppId = '00000003-0000-0000-c000-000000000000'; Roles = @(
      'ThreatHunting.Read.All',            # POST /security/runHuntingQuery
      'SecurityIncident.Read.All',         # GET  /security/incidents/{id}?$expand=alerts
      'ThreatIntelligence.Read.All',       # TI host reputation
      'SecurityAnalyzedMessage.Read.All',  # analyzedEmails
      'ThreatSubmission.Read.All') }       # emailThreats
)
$legacyApiAppIds = @('8ee8fdad-f234-4243-8f3b-15c294843740', 'fc780465-2017-40d4-a0c5-307022471b92')
$mi = Invoke-Graph GET "$graph/servicePrincipals/$FunctionPrincipalId`?`$select=id,displayName"
if (-not $mi) { throw "Managed identity service principal not found: $FunctionPrincipalId" }
$existing = @((Invoke-Graph GET "$graph/servicePrincipals/$FunctionPrincipalId/appRoleAssignments").value)
Write-Host "Target identity: " -NoNewline; Write-Host "$($mi.displayName) ($FunctionPrincipalId)" -ForegroundColor Cyan

foreach ($target in $targets) {
  $filter = [uri]::EscapeDataString("appId eq '$($target.AppId)'")
  $api = @((Invoke-Graph GET "$graph/servicePrincipals?`$filter=$filter&`$select=id,appId,displayName,appRoles").value) | Select-Object -First 1
  if (-not $api) { throw "API service principal not found for appId $($target.AppId)" }
  Write-Host ""
  Write-Host "$($api.displayName)" -ForegroundColor Magenta
  foreach ($roleName in $target.Roles) {
    $role = $api.appRoles | Where-Object { $_.value -eq $roleName -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
    if (-not $role) { throw "App role '$roleName' unavailable on '$($api.displayName)' in this tenant; verify current Microsoft API permissions and adjust before proceeding." }
    if ($existing | Where-Object { $_.resourceId -eq $api.id -and $_.appRoleId -eq $role.id }) {
      Write-Host "  [=] " -ForegroundColor DarkGray -NoNewline; Write-Host "$roleName" -NoNewline; Write-Host "  already assigned" -ForegroundColor DarkGray
      $skipped++
      continue
    }
    $null = Invoke-Graph POST "$graph/servicePrincipals/$FunctionPrincipalId/appRoleAssignments" @{ principalId = $FunctionPrincipalId; resourceId = $api.id; appRoleId = $role.id }
    Write-Host "  [+] " -ForegroundColor Green -NoNewline; Write-Host "$roleName" -NoNewline; Write-Host "  assigned" -ForegroundColor Green
    $assigned++
  }
}
# Remove app roles on legacy Defender APIs (Microsoft Threat Protection / WindowsDefenderATP).
$removed = 0
foreach ($legacyAppId in $legacyApiAppIds) {
  $filter = [uri]::EscapeDataString("appId eq '$legacyAppId'")
  $legacyApi = @((Invoke-Graph GET "$graph/servicePrincipals?`$filter=$filter&`$select=id,displayName,appRoles").value) | Select-Object -First 1
  if (-not $legacyApi) { continue }
  foreach ($assignment in @($existing | Where-Object { $_.resourceId -eq $legacyApi.id })) {
    $roleName = ($legacyApi.appRoles | Where-Object { $_.id -eq $assignment.appRoleId } | Select-Object -First 1).value
    $null = Invoke-Graph DELETE "$graph/servicePrincipals/$FunctionPrincipalId/appRoleAssignments/$($assignment.id)"
    Write-Host ''
    Write-Host "  [-] " -ForegroundColor Yellow -NoNewline; Write-Host "$roleName" -NoNewline; Write-Host "  removed from $($legacyApi.displayName) (legacy API, not used)" -ForegroundColor Yellow
    $removed++
  }
}

Write-Host ''
Write-Host "Done: " -NoNewline; Write-Host "$assigned assigned" -ForegroundColor Green -NoNewline; Write-Host ', ' -NoNewline; Write-Host "$skipped already present" -ForegroundColor DarkGray -NoNewline; Write-Host ", $removed legacy removed" -ForegroundColor Yellow
Write-Host 'Allow several minutes for permissions to propagate, then validate tokens and API calls.' -ForegroundColor Yellow
