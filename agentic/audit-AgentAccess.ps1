<#
.SYNOPSIS
  Read-only check of one Microsoft Entra agent identity and its paired agent user.

.DESCRIPTION
  Prints the blueprint link (publisher, secrets and certificates when the blueprint
  application is in this tenant) and, for BOTH principals, API permissions (direct and
  inherited from the blueprint, beta), groups, Entra roles, Azure RBAC and Defender
  unified RBAC (URBAC), with colour highlights and a flags summary.

  Colours:  Red = write-capable or highly privileged   Yellow = sensitive or broad
            Gray = informational                       DarkGray = nothing found

.PARAMETER AgentId
  Object ID of the agent identity.

.PARAMETER NoColor
  Plain text output. Also honoured: the NO_COLOR environment variable.

.PARAMETER Auth
  Sign-in method when no suitable session exists. Auto (default) opens the browser, but
  uses device code in WSL, over SSH or without a display. A failed browser sign-in falls
  back to device code. An existing Graph or Azure CLI session with the needed scopes is reused.

.NOTES
  Needs Microsoft Graph PowerShell and an `az login` session (for Azure RBAC).
  Delegated scopes: Application.Read.All, Directory.Read.All, User.Read.All,
  RoleManagement.Read.Directory, RoleManagement.Read.Defender
#>
param(
  [Parameter(Mandatory)][string]$AgentId,
  [switch]$NoColor,
  [ValidateSet('Auto', 'Browser', 'DeviceCode')][string]$Auth = 'Auto'
)

$g = 'https://graph.microsoft.com'
$useColor = -not $NoColor -and -not $env:NO_COLOR
$flags = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------- output helpers
function Out-Line([string]$Text = '', [string]$Color = 'Gray') {
  if ($useColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Out-Section([string]$Title) {
  Out-Line ''
  Out-Line ('=' * 78) Cyan
  Out-Line "  $Title" Cyan
  Out-Line ('=' * 78) Cyan
}
function Out-Group([string]$Title) { Out-Line ''; Out-Line $Title.ToUpper() Yellow }
function Out-Label([string]$Title) { Out-Line ''; Out-Line "  $Title" White }
function Out-Info([string]$Key, [string]$Value, [string]$Color = 'Gray') {
  Out-Line ('  {0,-14} {1}' -f $Key, $Value) $Color
}
# Print a list of items, each with its own colour. $ColorOf returns the colour for an item.
function Out-Items($Items, [scriptblock]$ColorOf = { 'Gray' }) {
  $list = @($Items | Where-Object { $_ })
  if (-not $list) { Out-Line '    none found' DarkGray; return }
  foreach ($i in $list) { Out-Line "    - $i" (& $ColorOf $i) }
}

# ---------------------------------------------------------------- data helpers
function Get-All($uri) {
  $items = @()
  while ($uri) { $p = Invoke-MgGraphRequest -Uri $uri; $items += $p.value; $uri = $p.'@odata.nextLink' }
  $items
}
$roleCache = @{}
function Get-RoleName($resourceId, $roleId) {
  if (-not $roleCache.ContainsKey($resourceId)) {
    $roleCache[$resourceId] = (Invoke-MgGraphRequest -Uri "$g/v1.0/servicePrincipals/$resourceId`?`$select=appRoles").appRoles
  }
  $r = $roleCache[$resourceId] | Where-Object { $_.id -eq $roleId } | Select-Object -First 1
  if ($r) { $r.value } else { 'default access' }
}
function Short-Scope([string]$s) { $s -replace '/subscriptions/([0-9a-fA-F]{8})[0-9a-fA-F-]{28}', '<sub:$1>' }

# ---------------------------------------------------------------- sign in and collect principals
function Test-DeviceCodePreferred {
  if ($Auth -eq 'DeviceCode') { return $true }
  if ($Auth -eq 'Browser') { return $false }
  if ($env:WSL_DISTRO_NAME -or $env:WSL_INTEROP) { return $true }
  if ($IsLinux -and (Test-Path /proc/version) -and (Select-String -Path /proc/version -Pattern 'microsoft|wsl' -Quiet)) { return $true }
  if ($env:SSH_CONNECTION -or $env:SSH_TTY) { return $true }
  if ($IsLinux -and -not $env:DISPLAY -and -not $env:WAYLAND_DISPLAY) { return $true }
  $false
}
$useDevice = Test-DeviceCodePreferred

function Connect-AuditGraph([string[]]$Scopes) {
  if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw 'Module Microsoft.Graph.Authentication is missing. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
  }
  $ctx = Get-MgContext
  if ($ctx -and -not @($Scopes | Where-Object { $_ -notin $ctx.Scopes })) { return }   # reuse the session
  if ($useDevice) {
    Write-Host 'Microsoft Graph sign-in: device code' -ForegroundColor Cyan
    Connect-MgGraph -Scopes $Scopes -UseDeviceCode -NoWelcome
  } else {
    Write-Host 'Microsoft Graph sign-in: browser' -ForegroundColor Cyan
    try { Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop }
    catch {
      Write-Warning "Browser sign-in failed ($($_.Exception.Message)); falling back to device code."
      Connect-MgGraph -Scopes $Scopes -UseDeviceCode -NoWelcome
    }
  }
  if (-not (Get-MgContext)) { throw 'Microsoft Graph sign-in failed: no active session.' }
  $missing = @($Scopes | Where-Object { $_ -notin (Get-MgContext).Scopes })
  if ($missing) { Write-Warning "Graph scopes not granted: $($missing -join ', '). Related checks will be incomplete." }
}

Connect-AuditGraph @('Application.Read.All', 'Directory.Read.All', 'User.Read.All',
  'RoleManagement.Read.Directory', 'RoleManagement.Read.Defender')

# Azure CLI session for Azure RBAC
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI (az) is missing.' }
az account show 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  if ($useDevice) { az login --use-device-code --allow-no-subscriptions | Out-Null }
  else {
    az login --allow-no-subscriptions | Out-Null
    if ($LASTEXITCODE -ne 0) { az login --use-device-code --allow-no-subscriptions | Out-Null }
  }
}

$identity = $null
try { $identity = Invoke-MgGraphRequest -Uri "$g/v1.0/servicePrincipals/$AgentId/microsoft.graph.agentIdentity?`$select=displayName,accountEnabled,createdDateTime,agentIdentityBlueprintId" } catch {}

$principals = @([pscustomobject]@{ Label = 'AGENT IDENTITY'; Id = $AgentId; Kind = 'servicePrincipals'; Info = $identity })
$user = Get-All "$g/v1.0/users/microsoft.graph.agentUser?`$filter=identityParentId eq '$AgentId'&`$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses" | Select-Object -First 1
if ($user) {
  $principals += [pscustomobject]@{ Label = 'AGENT USER'; Id = $user.id; Kind = 'users'; Info = $user }
} else {
  $flags.Add('no agent user is linked to this agent identity (only the identity can hold access)')
}

# Defender URBAC: assignments and role definitions, matched client-side
$urbacBase = "$g/beta/roleManagement/defender"
$urbac = @(); $defs = @{}; $urbacOk = $true
try {
  $urbac = Get-All "$urbacBase/roleAssignments"
  Get-All "$urbacBase/roleDefinitions" | ForEach-Object { $defs[$_.id] = $_ }
} catch {
  $urbacOk = $false
  $flags.Add('Defender URBAC could not be read (RoleManagement.Read.Defender missing?), so it was not checked')
}

$subs = az account list --query "[?state=='Enabled'].id" -o tsv

# ---------------------------------------------------------------- colour rules
$appRoleColor = {
  param($i)
  if ($i -match 'ReadWrite|\.Write') { 'Red' }
  elseif ($i -match 'RoleManagement|AuditLog|DelegatedPermissionGrant|Directory|Policy|Mail|Files') { 'Yellow' }
  else { 'Gray' }
}
$grantColor    = { param($i) if ($i -match 'AllPrincipals') { 'Yellow' } else { 'Gray' } }
$groupColor    = { param($i) if ($i -match '^All Users') { 'Yellow' } else { 'Gray' } }
$entraColor    = { param($i) if ($i -match 'Administrator|Owner') { 'Red' } else { 'Yellow' } }
$azureColor    = { param($i) if ($i -match '^(Owner|Contributor|User Access Administrator|Role Based Access Control Administrator) @') { 'Red' } else { 'Gray' } }

# ---------------------------------------------------------------- header
Out-Section 'AGENT ACCESS CHECK'
Out-Info 'Agent ID' $AgentId

# ---------------------------------------------------------------- blueprint
Out-Section 'BLUEPRINT'
$bpId = if ($identity) { $identity.agentIdentityBlueprintId } else { $null }
if (-not $bpId) {
  Out-Line '    none found' DarkGray
} else {
  $myTenant = (Get-MgContext).TenantId
  $bpp = $null; $bp = $null
  try { $bpp = Get-All "$g/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?`$filter=appId eq '$bpId'&`$select=id,displayName,appOwnerOrganizationId,createdDateTime" | Select-Object -First 1 } catch {}
  try { $bp = Get-All "$g/v1.0/applications/microsoft.graph.agentIdentityBlueprint?`$filter=appId eq '$bpId'&`$select=id,displayName,signInAudience,passwordCredentials,keyCredentials" | Select-Object -First 1 } catch {}
  Out-Info 'Blueprint ID' $bpId
  Out-Info 'Name' $(if ($bpp) { $bpp.displayName } else { 'unknown' })
  $owner = if ($bpp) { $bpp.appOwnerOrganizationId } else { $null }
  if ($owner) {
    if ($owner -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a') { Out-Info 'Published by' "$owner (Microsoft)" }
    elseif ($owner -eq $myTenant) { Out-Info 'Published by' "$owner (this tenant)" }
    else {
      Out-Info 'Published by' "$owner (another tenant)" Yellow
      $flags.Add("blueprint is published by another tenant ($owner); its credentials are outside your control")
    }
  }
  if ($bp) {
    Out-Info 'Application' "in this tenant ($($bp.signInAudience))"
    $secrets = @($bp.passwordCredentials); $certs = @($bp.keyCredentials)
    Out-Info 'Client secrets' $secrets.Count $(if ($secrets.Count -gt 0) { 'Red' } else { 'Gray' })
    foreach ($s in $secrets) { Out-Line "    secret $(if ($s.displayName) { $s.displayName } else { '(no name)' }), expires $($s.endDateTime)" Yellow }
    Out-Info 'Certificates' $certs.Count
    foreach ($c in $certs) { Out-Line "    certificate $(if ($c.displayName) { $c.displayName } else { '(no name)' }), expires $($c.endDateTime)" Gray }
    if ($secrets.Count -gt 0) { $flags.Add("blueprint has $($secrets.Count) client secret(s); a blueprint credential can authenticate all its agent identities, prefer certificates or federated credentials") }
  } else {
    Out-Info 'Application' 'not in this tenant (only the principal is)'
    Out-Info 'Credentials' 'held by the publishing tenant, not visible here' DarkGray
  }
}

# ---------------------------------------------------------------- per-principal audit
foreach ($p in $principals) {
  $id = $p.Id
  $name = if ($p.Info) { $p.Info.displayName } else { '(name not readable)' }
  Out-Section "$($p.Label): $name"
  Out-Info 'Object ID' $id
  if ($p.Info) {
    Out-Info 'Enabled' $p.Info.accountEnabled $(if ($p.Info.accountEnabled -eq $false) { 'Red' } else { 'Gray' })
    if ($p.Kind -eq 'users') {
      Out-Info 'UPN' $p.Info.userPrincipalName
      $lic = @($p.Info.assignedLicenses).Count
      Out-Info 'Licenses' $lic $(if ($lic -gt 0) { 'Yellow' } else { 'Gray' })
      if ($lic -gt 0) { $flags.Add("agent user has $lic assigned license(s)") }
    }
  }

  # --- API permissions
  Out-Group 'API permissions'
  Out-Label 'App roles'
  $appRoles = Get-All "$g/v1.0/$($p.Kind)/$id/appRoleAssignments" |
    ForEach-Object { "$($_.resourceDisplayName): $(Get-RoleName $_.resourceId $_.appRoleId)" } | Sort-Object
  Out-Items $appRoles $appRoleColor
  $appRoles | Where-Object { $_ -match 'ReadWrite|\.Write' } | ForEach-Object { $flags.Add("$($p.Label): write-capable API permission $_") }

  if ($p.Kind -eq 'servicePrincipals') {
    Out-Label 'Delegated grants'
    $grants = Get-All "$g/v1.0/servicePrincipals/$id/oauth2PermissionGrants" |
      ForEach-Object { "$("$($_.scope)".Trim()) ($($_.consentType))" }
    Out-Items $grants $grantColor

    # Inherited from the blueprint (Graph beta, read-only)
    $inhBase = "$g/beta/servicePrincipals/microsoft.graph.agentIdentity/$id"
    Out-Label 'App roles inherited from blueprint (beta)'
    $inhRoles = try {
      Get-All "$inhBase/inheritedAppRoleAssignments" |
        ForEach-Object { "$($_.resourceDisplayName): $(Get-RoleName $_.resourceId $_.appRoleId)" } | Sort-Object
    } catch { $null }
    Out-Items $inhRoles $appRoleColor
    @($inhRoles) | Where-Object { $_ -match 'ReadWrite|\.Write' } | ForEach-Object { $flags.Add("$($p.Label): write-capable inherited API permission $_") }

    Out-Label 'Delegated grants inherited from blueprint (beta)'
    $inhGrants = try {
      Get-All "$inhBase/inheritedOauth2PermissionGrants" |
        ForEach-Object { "$("$($_.scope)".Trim()) ($($_.consentType))" }
    } catch { $null }
    Out-Items $inhGrants $grantColor
  }

  # --- Entra ID
  Out-Group 'Entra ID'
  Out-Label 'Groups'
  $groups = Get-All "$g/v1.0/$($p.Kind)/$id/transitiveMemberOf" | ForEach-Object { $_.displayName } | Sort-Object
  Out-Items $groups $groupColor
  if ($p.Kind -eq 'users' -and ($groups -contains 'All Users')) {
    $flags.Add("AGENT USER: member of 'All Users' (anything shared with that group is inherited)")
  }

  Out-Label 'Directory roles'
  $entra = Get-All "$g/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$id'&`$expand=roleDefinition" |
    ForEach-Object { "$($_.roleDefinition.displayName) @ $($_.directoryScopeId)" }
  Out-Items $entra $entraColor
  @($entra) | Where-Object { $_ } | ForEach-Object { $flags.Add("$($p.Label): holds Entra role $_") }

  # --- Azure
  Out-Group 'Azure'
  Out-Label "Role assignments ($(@($subs).Count) subscriptions checked)"
  $azure = foreach ($s in $subs) {
    [string[]]$extra = if ($p.Kind -eq 'users') { '--include-groups' } else { @() }
    az role assignment list --subscription $s --all --include-inherited @extra --assignee $id -o json 2>$null |
      ConvertFrom-Json | ForEach-Object { "$($_.roleDefinitionName) @ $(Short-Scope $_.scope)" }
  }
  Out-Items $azure $azureColor
  @($azure) | Where-Object { $_ -match '^(Owner|Contributor|User Access Administrator|Role Based Access Control Administrator) @' } |
    ForEach-Object { $flags.Add("$($p.Label): privileged Azure role $_") }

  # --- Defender XDR
  Out-Group 'Defender XDR'
  Out-Label 'Unified RBAC (URBAC)'
  $mine = @($urbac | Where-Object { $_.principalId -eq $id -or $_.principalIds -contains $id })
  if (-not $urbacOk) { Out-Line '    not checked (URBAC not readable with this sign-in)' Yellow }
  elseif (-not $mine) { Out-Line '    none found' DarkGray }
  foreach ($a in $mine) {
    $d = $defs[$a.roleDefinitionId]
    Out-Line "    - $($d.displayName)" Cyan
    Out-Line "        scope: $($a.appScopeIds -join ', ')" Gray
    foreach ($act in ($d.rolePermissions.allowedResourceActions | Sort-Object -Unique)) {
      $c = if ($act -match '/manage$|/write$|/delete$') { 'Red' } elseif ($act -match 'rawdata/') { 'Yellow' } else { 'Gray' }
      Out-Line "        $act" $c
      if ($c -eq 'Red')    { $flags.Add("$($p.Label): URBAC role '$($d.displayName)' can $act") }
      if ($c -eq 'Yellow') { $flags.Add("$($p.Label): URBAC role '$($d.displayName)' can read raw data ($act)") }
    }
  }
}

# ---------------------------------------------------------------- flags summary
Out-Section 'FLAGS'
$unique = @($flags | Select-Object -Unique)
if ($unique) { foreach ($f in $unique) { Out-Line "  ! $f" Red } }
else { Out-Line '  nothing flagged' Green }
Out-Line ''
Out-Line 'Not covered: PIM-eligible roles, access packages, Conditional Access, Foundry or Copilot Studio RBAC.' DarkGray
Out-Line ''
