<#
.SYNOPSIS
  Deletes everything deploy.ps1 (and optionally reporting-mailbox-access.ps1) created.

.DESCRIPTION
  Names come from deployment.env (written by deploy.ps1 next to this script); -ResourceGroup and
  -SubscriptionId override it. The live resource-group inventory is shown as a cross-check.
  1. Records the Function identity's app ID and the soft-deletable resources in the resource group.
  2. Optional (-IncludeExchange): removes the Exchange RBAC objects for the reporting mailbox
     (management role assignment, management scope, Exchange service principal). These live in
     Exchange Online, outside Azure, and survive a resource-group delete.
  3. Deletes the resource group: Foundry account/project/model/agents/connection, Function App + plan,
     storage, user-assigned identity, Key Vault, Application Insights, and all role assignments in it.
     The Function's Graph/Defender app-role assignments disappear with its managed identity.
  4. Purges the soft-deleted Key Vault and Foundry account so names and model quota are released
     (skip with -NoPurge).
  5. Deletes the Entra Agent ID objects Foundry created for the agents (agent identities, agent identity
     blueprint principals and blueprint applications, found by the name prefix '<foundry-name>-').
     Deleting the Foundry account does NOT remove them. Entra keeps them restorable for 30 days;
     -PurgeEntra deletes them permanently. Needs an Entra role that can manage agent identities.

  Irreversible. Prompts for the resource-group name unless -Force is given. On success deployment.env is
  renamed to deployment.env.removed-<timestamp> as a record.

.EXAMPLE
  ./teardown.ps1
  Everything from deployment.env.
.EXAMPLE
  ./teardown.ps1 -IncludeExchange -UseDeviceCode
.EXAMPLE
  ./teardown.ps1 -ResourceGroup ps-foundry-agents
  Without deployment.env (names discovered from the resource group).
.EXAMPLE
  ./teardown.ps1 -EntraOnly
  Only remove leftover agent identities / blueprints of an already deleted Foundry account. Names come from
  deployment.env, or from the newest deployment.env.removed-<timestamp> record; -FoundryName overrides.
#>
param(
  [string]$ResourceGroup,
  [string]$SubscriptionId,
  [string]$EnvFile = (Join-Path $PSScriptRoot 'deployment.env'),
  # Also remove the Exchange RBAC grant for the reporting mailbox (needs ExchangeOnlineManagement + Exchange admin).
  [switch]$IncludeExchange,
  # Device-code sign-in for Exchange (also automatic fallback; EXO_USE_DEVICE_CODE=1 makes it the default).
  [switch]$UseDeviceCode,
  # Leave soft-deleted Key Vault / Foundry account recoverable instead of purging them.
  [switch]$NoPurge,
  # Skip the confirmation prompt.
  [switch]$Force,
  # Foundry account name(s) whose agent identities/blueprints to remove (default: from deployment.env / inventory).
  [string[]]$FoundryName,
  # Only remove the Entra agent identity objects (e.g. leftovers of an earlier teardown); no Azure resources.
  [switch]$EntraOnly,
  # Permanently delete the Entra agent objects instead of leaving them restorable for 30 days.
  [switch]$PurgeEntra
)
$ErrorActionPreference = 'Stop'
function Write-Step([string]$Text) { Write-Host ''; Write-Host $Text -ForegroundColor Magenta }
function Write-Ok([string]$Text) { Write-Host '  [-] ' -ForegroundColor Green -NoNewline; Write-Host $Text }
function Write-Same([string]$Text) { Write-Host '  [=] ' -ForegroundColor DarkGray -NoNewline; Write-Host $Text -ForegroundColor DarkGray }
function Write-Warn([string]$Text) { Write-Host '  [!] ' -ForegroundColor Yellow -NoNewline; Write-Host $Text -ForegroundColor Yellow }

# Entra Agent ID objects Foundry creates per agent: names start with '<foundry-account>-<project>-<agent>'.
function Get-AgentIdObjects([string]$Prefix) {
  $kinds = [ordered]@{
    'agent identity'            = 'servicePrincipals/microsoft.graph.agentIdentity'
    'blueprint principal'       = 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal'
    'blueprint application'     = 'applications/microsoft.graph.agentIdentityBlueprint'
  }
  $found = @()
  $filter = [uri]::EscapeDataString("startswith(displayName,'$Prefix')")
  foreach ($kind in $kinds.Keys) {
    $out = az rest --url "https://graph.microsoft.com/beta/$($kinds[$kind])?`$filter=$filter&`$select=id,displayName&`$count=true" `
      --headers 'ConsistencyLevel=eventual' --output json --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Warn "Could not list $kind objects (missing Entra permission?)"; continue }
    foreach ($o in (($out -join "`n") | ConvertFrom-Json).value) {
      $found += [pscustomobject]@{ Kind = $kind; Id = $o.id; Name = $o.displayName }
    }
  }
  return $found
}

# --- Names from deployment.env ---------------------------------------------
$deployed = @{}
$fromArchive = $false
if (-not (Test-Path -LiteralPath $EnvFile) -and -not $ResourceGroup) {
  # After a full teardown the file is archived as deployment.env.removed-<timestamp>; use the newest record.
  $record = Get-ChildItem -Path "$EnvFile.removed-*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
  if ($record) { $EnvFile = $record.FullName; $fromArchive = $true }
}
if (Test-Path -LiteralPath $EnvFile) {
  foreach ($line in Get-Content -LiteralPath $EnvFile) {
    if ($line -match '^\s*([A-Z_]+)=(.*)$') { $deployed[$Matches[1]] = $Matches[2].Trim() }
  }
  Write-Host "Read $EnvFile (deployed $($deployed.DEPLOYED_AT_UTC))" -ForegroundColor DarkGray
} else {
  Write-Host "No $EnvFile; names are discovered from the resource group." -ForegroundColor DarkGray
}
if (-not $ResourceGroup) { $ResourceGroup = $deployed.AZURE_RESOURCE_GROUP }
if (-not $SubscriptionId) { $SubscriptionId = if ($deployed.AZURE_SUBSCRIPTION_ID) { $deployed.AZURE_SUBSCRIPTION_ID } else { $env:AZURE_SUBSCRIPTION_ID } }
if (-not $ResourceGroup -and -not $EntraOnly) { throw 'No resource group: pass -ResourceGroup, keep deployment.env next to this script, or use -EntraOnly -FoundryName <name> for leftover agent identities.' }

if ($SubscriptionId) {
  az account set --subscription $SubscriptionId --only-show-errors
  if ($LASTEXITCODE -ne 0) { throw 'az account set failed.' }
}
$account = az account show --query "{name:name, id:id}" --output json --only-show-errors | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Not logged in to Azure CLI. Run az login first.' }
if (-not $EntraOnly -and $fromArchive -and (az group exists --name $ResourceGroup --only-show-errors) -ne 'true') {
  # The archived deployment is already gone; only its Entra agent objects can be left over.
  Write-Warn "Resource group '$ResourceGroup' from the archived record no longer exists - the deployment was already torn down."
  Write-Warn 'Switching to -EntraOnly: checking for leftover agent identities / blueprints.'
  $EntraOnly = $true
}
if (-not $EntraOnly -and (az group exists --name $ResourceGroup --only-show-errors) -ne 'true') { throw "Resource group '$ResourceGroup' not found in subscription $($account.name). Use -EntraOnly -FoundryName <name> to remove only leftover agent identities." }

# --- Inventory (before anything is deleted) ---------------------------------
$resources = @(); $vaults = @(); $foundries = @(); $functionApps = @(); $functionAppIds = @()
if (-not $EntraOnly) {
Write-Step "Inventory of $ResourceGroup (subscription $($account.name))"
$resources = az resource list --resource-group $ResourceGroup --query "[].{name:name, type:type, location:location}" --output json --only-show-errors | ConvertFrom-Json
$resources | Sort-Object type | ForEach-Object { Write-Host ("  {0,-55} {1}" -f $_.type, $_.name) }
$vaults = @($resources | Where-Object type -eq 'Microsoft.KeyVault/vaults')
$foundries = @($resources | Where-Object type -eq 'Microsoft.CognitiveServices/accounts')
$functionApps = @($resources | Where-Object type -eq 'Microsoft.Web/sites')
# Recorded names also cover resources already gone from the group (e.g. a partial earlier teardown).
if ($deployed.KEY_VAULT_NAME -and -not ($vaults | Where-Object name -eq $deployed.KEY_VAULT_NAME)) {
  $vaults += [pscustomobject]@{ name = $deployed.KEY_VAULT_NAME; location = $deployed.LOCATION }
}
if ($deployed.FOUNDRY_NAME -and -not ($foundries | Where-Object name -eq $deployed.FOUNDRY_NAME)) {
  $foundries += [pscustomobject]@{ name = $deployed.FOUNDRY_NAME; location = $deployed.LOCATION }
}
$functionAppIds = @()
if ($deployed.FUNCTION_APP_ID) { $functionAppIds += $deployed.FUNCTION_APP_ID }
foreach ($app in $functionApps) {
  $principalId = az functionapp identity show --resource-group $ResourceGroup --name $app.name --query principalId --output tsv --only-show-errors 2>$null
  if ($principalId) {
    $appId = az ad sp show --id $principalId --query appId --output tsv --only-show-errors 2>$null
    if ($appId -and $appId -notin $functionAppIds) { $functionAppIds += $appId }
  }
}

if ($functionAppIds) { Write-Host "  Function identity appId(s): $($functionAppIds -join ', ')" }
}

# Entra agent identity objects (outside the resource group)
if (-not $FoundryName) { $FoundryName = @($foundries | ForEach-Object { $_.name }) + @($deployed.FOUNDRY_NAME) | Where-Object { $_ } | Select-Object -Unique }
if (-not $FoundryName) { throw 'No Foundry account name: pass -FoundryName or keep deployment.env next to this script.' }
Write-Step 'Entra agent identity objects (created by Foundry, outside the resource group)'
$agentObjects = @()
foreach ($name in $FoundryName) { $agentObjects += Get-AgentIdObjects "$name-" }
if ($agentObjects) { $agentObjects | ForEach-Object { Write-Host ("  {0,-22} {1}" -f $_.Kind, $_.Name) } }
else { Write-Same "None found for prefix(es): $(($FoundryName | ForEach-Object { "$_-" }) -join ', ')" }
if ($deployed.Count -and -not $EntraOnly) {
  $missing = @('FOUNDRY_NAME','FUNCTION_APP_NAME','KEY_VAULT_NAME','STORAGE_ACCOUNT_NAME') |
    Where-Object { $deployed[$_] -and -not ($resources | Where-Object name -eq $deployed[$_]) }
  foreach ($key in $missing) { Write-Warn "$key $($deployed[$key]) from deployment.env is not in the resource group (already deleted?)" }
}

if (-not $Force) {
  Write-Host ''
  if ($EntraOnly) {
    Write-Host ''
    Write-Host "This deletes the $($agentObjects.Count) Entra agent object(s) listed above$(if ($PurgeEntra) { ' permanently' } else { ' (restorable for 30 days)' })." -ForegroundColor Red
    $answer = Read-Host 'Type the Foundry account name to confirm'
    if ($answer -notin $FoundryName) { Write-Host 'Aborted; nothing was deleted.' -ForegroundColor Yellow; return }
  } else {
  Write-Host "This permanently deletes resource group '$ResourceGroup' and everything in it$(if (-not $NoPurge) { ', and purges the soft-deleted Key Vault and Foundry account' })$(if ($IncludeExchange) { ', plus the Exchange RBAC grant' })." -ForegroundColor Red
  $answer = Read-Host "Type the resource group name to confirm"
  if ($answer -ne $ResourceGroup) { Write-Host 'Aborted; nothing was deleted.' -ForegroundColor Yellow; return }
  }
}

# --- Exchange RBAC (outside Azure) ------------------------------------------
if (-not $EntraOnly -and $IncludeExchange) {
  Write-Step 'Exchange RBAC for the reporting mailbox'
  if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module ExchangeOnlineManagement
  $exo = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' } | Select-Object -First 1
  if (-not $exo) {
    # Interactive by default; device code with -UseDeviceCode or EXO_USE_DEVICE_CODE=1, and as automatic
    # fallback when the interactive sign-in fails (no browser, e.g. WSL / lab hosts).
    $useDevice = $UseDeviceCode -or $env:EXO_USE_DEVICE_CODE -in '1', 'true', 'yes'
    if ($useDevice) {
      Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
    } else {
      try { Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop }
      catch {
        Write-Host "  Interactive sign-in failed ($($_.Exception.Message.Split([Environment]::NewLine)[0])) - falling back to device code." -ForegroundColor Yellow
        Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
      }
    }
  }
  $assignmentName = if ($deployed.EXCHANGE_ROLE_ASSIGNMENT_NAME) { $deployed.EXCHANGE_ROLE_ASSIGNMENT_NAME } else { 'PhishingTriage-ReportingMailbox-MailRead' }
  $scopeName = if ($deployed.EXCHANGE_SCOPE_NAME) { $deployed.EXCHANGE_SCOPE_NAME } else { 'PhishingTriage-ReportingMailbox' }
  if (Get-ManagementRoleAssignment -Identity $assignmentName -ErrorAction SilentlyContinue) {
    Remove-ManagementRoleAssignment -Identity $assignmentName -Confirm:$false; Write-Ok "Removed role assignment $assignmentName"
  } else { Write-Same "Role assignment $assignmentName not found" }
  if (Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue) {
    Remove-ManagementScope -Identity $scopeName -Confirm:$false; Write-Ok "Removed management scope $scopeName"
  } else { Write-Same "Management scope $scopeName not found" }
  foreach ($appId in $functionAppIds) {
    $sp = try { Get-ServicePrincipal -Identity $appId -ErrorAction Stop } catch { $null }
    if ($sp) { Remove-ServicePrincipal -Identity $appId -Confirm:$false; Write-Ok "Removed Exchange service principal $appId" }
    else { Write-Same "Exchange service principal $appId not found" }
  }
} elseif (-not $EntraOnly -and $functionAppIds) {
  Write-Warn 'Exchange RBAC objects (if reporting-mailbox-access.ps1 -Apply was run) are kept. Re-run with -IncludeExchange to remove them.'
}

# --- Resource group ---------------------------------------------------------
if (-not $EntraOnly) {
Write-Step "Deleting resource group $ResourceGroup (takes a few minutes)"
az group delete --name $ResourceGroup --yes --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'Resource group deletion failed.' }
Write-Ok "Resource group $ResourceGroup deleted"

# --- Purge soft-deleted resources -------------------------------------------
if ($NoPurge) {
  Write-Warn 'Soft-deleted Key Vault and Foundry account kept (recoverable; names and model quota stay reserved).'
} else {
  Write-Step 'Purging soft-deleted resources'
  foreach ($vault in $vaults) {
    az keyvault purge --name $vault.name --location $vault.location --only-show-errors
    if ($LASTEXITCODE -eq 0) { Write-Ok "Purged Key Vault $($vault.name)" } else { Write-Warn "Could not purge Key Vault $($vault.name) (purge protection or missing permission)" }
  }
  foreach ($foundry in $foundries) {
    az cognitiveservices account purge --name $foundry.name --resource-group $ResourceGroup --location $foundry.location --only-show-errors
    if ($LASTEXITCODE -eq 0) { Write-Ok "Purged Foundry account $($foundry.name)" } else { Write-Warn "Could not purge Foundry account $($foundry.name)" }
  }
}
}

# --- Entra agent identity objects --------------------------------------------
if ($agentObjects) {
  Write-Step 'Deleting Entra agent identity objects'
  # Children first: agent identities, then blueprint principal, then blueprint application.
  foreach ($kind in 'agent identity', 'blueprint principal', 'blueprint application') {
    foreach ($o in @($agentObjects | Where-Object Kind -eq $kind)) {
      $url = switch ($kind) {
        'agent identity'        { "https://graph.microsoft.com/beta/servicePrincipals/$($o.Id)/microsoft.graph.agentIdentity" }
        'blueprint principal'   { "https://graph.microsoft.com/v1.0/servicePrincipals/$($o.Id)" }
        'blueprint application' { "https://graph.microsoft.com/v1.0/applications/$($o.Id)" }
      }
      az rest --method DELETE --url $url --only-show-errors 2>$null
      if ($LASTEXITCODE -ne 0) {
        # A blueprint deletion can already have removed its children.
        if ((az rest --url "https://graph.microsoft.com/v1.0/directoryObjects/$($o.Id)" --only-show-errors 2>$null) -eq $null) { Write-Same "$kind $($o.Name) already gone"; continue }
        Write-Warn "Could not delete $kind $($o.Name) (needs an Entra role that can manage agent identities)"; continue
      }
      Write-Ok "Deleted $kind $($o.Name)"
      if ($PurgeEntra) {
        az rest --method DELETE --url "https://graph.microsoft.com/v1.0/directory/deletedItems/$($o.Id)" --only-show-errors 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Ok "  purged permanently" } else { Write-Warn "  could not purge (restorable for 30 days)" }
      }
    }
  }
  if (-not $PurgeEntra) { Write-Same 'Deleted agent objects stay restorable for 30 days (use -PurgeEntra to remove permanently).' }
}

if (-not $EntraOnly -and (Test-Path -LiteralPath $EnvFile)) {
  $record = "$EnvFile.removed-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
  Move-Item -LiteralPath $EnvFile -Destination $record
  Write-Ok "Kept a record: $(Split-Path $record -Leaf)"
}

Write-Host ''
Write-Host 'Teardown complete.' -ForegroundColor Green
Write-Host 'Not touched: Defender user-reported settings (reporting mailbox) and local files/env vars.' -ForegroundColor DarkGray
