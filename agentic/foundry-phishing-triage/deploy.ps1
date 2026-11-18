# Deploys (or re-deploys) the whole stack; safe to re-run.
#   ./deploy.ps1              infra (Bicep) -> Function code -> mcp_extension key -> Foundry User role -> new agent version
#   ./deploy.ps1 -AgentOnly   only publish a new agent version from agent-instructions.md (no infra/code, key unchanged)
#   ./deploy.ps1 -Yes         skip the confirmation prompt (automation)
#   ./deploy.ps1 -RotateKey   new MCP key (default: reuse the key in Key Vault)  |  -ForceCode: redeploy unchanged code
# Re-runs are idempotent: deterministic names (suffix from subscription + resource group), key reused,
# code only redeployed when function/ changed (hash in deployment.env), agent version only on definition changes.
#   ./deploy.ps1 -ReportingMailbox reports@contoso.com   set the Defender reporting mailbox (asked when not set)
# Names (all optional): AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, FOUNDRY_NAME, FUNCTION_APP_NAME, LOCATION.
#   Order: environment variable > deployment.env (written by every full deploy; no secrets) > current az context
#   (subscription) > generated defaults. The script shows the resolved values and asks before changing anything.
# Optional env: FOUNDRY_MODEL_VERSION (default 2026-07-09), MCP_API_KEY (default: reuse the key in Key Vault,
#   generated on first deploy; -RotateKey creates a new one), REPORTING_MAILBOX_UPN (unset = keep the app's current value; set to '-' to disable), AGENT_NAME
# Not part of this script: permissions.ps1 (Graph/Defender app roles) and reporting-mailbox-access.ps1 (Exchange RBAC).
#
# DEMO AUTH: Foundry calls the MCP endpoint with a shared key (x-functions-key = mcp_extension system key).
# For PRODUCTION use Microsoft Entra ID instead: Function built-in auth (Entra app, Application ID URI as
# audience), key access off (webhookAuthorizationLevel=Anonymous), only the Foundry project MI allowed, and a
# Foundry connection with project-managed-identity auth. See README 'Production: use Entra ID authentication'.
param(
    [switch]$AgentOnly,
    [switch]$Yes,
    # Defender reporting mailbox for list_reported_emails / get_reported_email. Asked interactively when not set.
    [string]$ReportingMailbox,
    # Agent name; overrides AGENT_NAME (default: ps-phishing-triage).
    [string]$AgentName,
    # Foundry project name; overrides PROJECT_NAME (default: defender-agents).
    [string]$ProjectName,
    # Generate a new MCP key (Key Vault, connection, Function). Default: reuse the existing key.
    [switch]$RotateKey,
    # Redeploy the Function code even if function/ is unchanged since the last deployment.
    [switch]$ForceCode
)
$ErrorActionPreference = 'Stop'

# --- Resolve names: env var > deployment.env > az context > generated default ---------------------------
$envFile = Join-Path $PSScriptRoot 'deployment.env'
$fromFile = @{}
if (Test-Path -LiteralPath $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile) {
        if ($line -match '^\s*([A-Z_]+)=(.*)$') { $fromFile[$Matches[1]] = $Matches[2].Trim() }
    }
}
$source = @{}
function Resolve-Setting([string]$Name, [scriptblock]$Default, [string]$DefaultSource, [switch]$NotFromFile) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if (-not [string]::IsNullOrWhiteSpace($value)) { $script:source[$Name] = 'environment'; return $value }
    # Infrastructure names are pinned by deployment.env; project and agent names follow the defaults.
    if (-not $NotFromFile -and $fromFile[$Name]) { $script:source[$Name] = 'deployment.env'; return $fromFile[$Name] }
    $script:source[$Name] = $DefaultSource
    return (& $Default)
}

$current = az account show --query "{id:id, name:name, tenant:tenantId, user:user.name}" --output json --only-show-errors | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $current) { throw 'Not logged in to Azure CLI. Run az login first.' }
$subscriptionId = Resolve-Setting 'AZURE_SUBSCRIPTION_ID' { $current.id } 'current az context'
if ($subscriptionId -ne $current.id) {
    az account set --subscription $subscriptionId --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "az account set failed for subscription $subscriptionId." }
}
$sub = az account show --query "{id:id, name:name, tenant:tenantId, user:user.name}" --output json --only-show-errors | ConvertFrom-Json

$resourceGroup   = Resolve-Setting 'AZURE_RESOURCE_GROUP' { 'rg-phishing-triage' } 'default'
# Deterministic suffix for generated names (like Bicep uniqueString): same subscription + resource group
# -> same names, even without deployment.env. Foundry names: lowercase alphanumeric, 3-24 chars.
$hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$subscriptionId/$($resourceGroup.ToLower())"))
$suffix = ([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 6).ToLower()
$location        = Resolve-Setting 'LOCATION' { 'swedencentral' } 'default'
$foundryName     = Resolve-Setting 'FOUNDRY_NAME' { "fdyphish$suffix" } 'generated (deterministic)'
$functionAppName = Resolve-Setting 'FUNCTION_APP_NAME' { "func-phish-mcp-$suffix" } 'generated (deterministic)'
$agentName       = if ($AgentName) { $source['AGENT_NAME'] = 'parameter'; $AgentName } else { Resolve-Setting 'AGENT_NAME' { 'ps-phishing-triage' } 'default' -NotFromFile }
$projectName     = if ($ProjectName) { $source['PROJECT_NAME'] = 'parameter'; $ProjectName } else { Resolve-Setting 'PROJECT_NAME' { 'defender-agents' } 'default' -NotFromFile }
$modelVersion = if ($env:FOUNDRY_MODEL_VERSION) { $env:FOUNDRY_MODEL_VERSION } else { '2026-07-09' }
$modelDeploymentName = 'gpt-5.6-luna'
$projectEndpoint = "https://$foundryName.services.ai.azure.com/api/projects/$projectName"
$mcpEndpoint = "https://$functionAppName.azurewebsites.net/runtime/webhooks/mcp"
$connectionName = 'phishing-triage-mcp'

# What already exists (update) vs. what will be created.
$rgExists = (az group exists --name $resourceGroup --only-show-errors) -eq 'true'
$foundryExists = $false; $functionExists = $false
if ($rgExists) {
    az cognitiveservices account show --resource-group $resourceGroup --name $foundryName --only-show-errors --output none 2>$null
    $foundryExists = $LASTEXITCODE -eq 0
    az functionapp show --resource-group $resourceGroup --name $functionAppName --only-show-errors --output none 2>$null
    $functionExists = $LASTEXITCODE -eq 0
}

if (-not $AgentOnly) {
    # Reporting mailbox: parameter > REPORTING_MAILBOX_UPN > current app setting > ask.
    $reportingMailboxUpn = ''; $mailboxNote = ''
    if ($ReportingMailbox -eq '-' -or $env:REPORTING_MAILBOX_UPN -eq '-') {
        $mailboxNote = 'disabled explicitly'
    } elseif ($ReportingMailbox) {
        $reportingMailboxUpn = $ReportingMailbox; $mailboxNote = 'parameter'
    } elseif (-not [string]::IsNullOrWhiteSpace($env:REPORTING_MAILBOX_UPN)) {
        $reportingMailboxUpn = $env:REPORTING_MAILBOX_UPN; $mailboxNote = 'environment'
    } else {
        if ($functionExists) {
            $reportingMailboxUpn = az functionapp config appsettings list --resource-group $resourceGroup --name $functionAppName `
                --query "[?name=='REPORTING_MAILBOX_UPN'].value | [0]" --output tsv --only-show-errors 2>$null
            if ($LASTEXITCODE -ne 0 -or $null -eq $reportingMailboxUpn) { $reportingMailboxUpn = '' }
            if ($reportingMailboxUpn) { $mailboxNote = 'kept from current app setting' }
        }
        if (-not $reportingMailboxUpn -and -not $Yes) {
            Write-Host ''
            Write-Host 'Defender reporting mailbox (where users'' "Report" submissions land). Needed for list_reported_emails /' -ForegroundColor DarkGray
            Write-Host 'get_reported_email; check Defender > Settings > Email & collaboration > User reported settings.' -ForegroundColor DarkGray
            while ($true) {
                $answer = (Read-Host 'Reporting mailbox UPN (Enter or n to skip)').Trim()
                if (-not $answer -or $answer -match '^(n|no)$') { break }
                if ($answer -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $reportingMailboxUpn = $answer; $mailboxNote = 'entered now'; break }
                Write-Host "  '$answer' doesn't look like a UPN / email address - try again or press Enter to skip." -ForegroundColor Yellow
            }
        }
        if (-not $reportingMailboxUpn) { $mailboxNote = 'not set - mailbox tools disabled'; $mailboxSkipped = $true }
    }
    if ($reportingMailboxUpn -and $reportingMailboxUpn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        throw "Reporting mailbox '$reportingMailboxUpn' doesn't look like a UPN / email address."
    }
    # MCP key: MCP_API_KEY > existing Key Vault secret (reuse) > new key. -RotateKey forces a new one.
    $apiKey = $env:MCP_API_KEY; $keyNote = 'from MCP_API_KEY'
    if ([string]::IsNullOrWhiteSpace($apiKey) -and -not $RotateKey -and $rgExists) {
        $vaultName = if ($fromFile['KEY_VAULT_NAME']) { $fromFile['KEY_VAULT_NAME'] } else {
            az keyvault list --resource-group $resourceGroup --query "[0].name" --output tsv --only-show-errors 2>$null }
        if ($vaultName) {
            $apiKey = az keyvault secret show --vault-name $vaultName --name mcp-api-key --query value --output tsv --only-show-errors 2>$null
            if ($LASTEXITCODE -eq 0 -and $apiKey) { $keyNote = "reused from Key Vault $vaultName - unchanged" }
            else { $apiKey = ''; $keyNote = "could not read Key Vault $vaultName (no Key Vault Secrets User yet?) - new key, rotated everywhere" }
        }
    }
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        # 48 random bytes, URL-safe base64 (64 chars). Never printed.
        $bytes = [byte[]]::new(48); [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $apiKey = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
        if (-not $keyNote -or $keyNote -eq 'from MCP_API_KEY') { $keyNote = if ($RotateKey) { 'new key (-RotateKey) - rotated in Key Vault, connection and Function' } else { 'new key - set in Key Vault, connection and Function' } }
    }
    # Code: skip the zip deploy when function/ is unchanged since the last deployment.
    $codeFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot 'function') -Recurse -File | Where-Object { $_.FullName -notmatch '__pycache__' } | Sort-Object FullName
    $codeBytes = foreach ($f in $codeFiles) { [Text.Encoding]::UTF8.GetBytes($f.Name); [IO.File]::ReadAllBytes($f.FullName) }
    $codeHash = ([BitConverter]::ToString([Security.Cryptography.SHA256]::HashData([byte[]]($codeBytes | ForEach-Object { $_ })))) -replace '-', ''
    $deployCode = $ForceCode -or -not $functionExists -or $fromFile['FUNCTION_CODE_SHA256'] -ne $codeHash
    $codeNote = if ($ForceCode) { 'redeploy (-ForceCode)' } elseif (-not $functionExists) { 'deploy (new Function App)' } elseif ($deployCode) { 'redeploy (function/ changed)' } else { 'unchanged - skipped (-ForceCode to redeploy)' }
    if ($apiKey.Length -lt 43) { throw 'MCP_API_KEY must be at least 43 characters (use a cryptographically random value).' }
}

# --- Summary + confirmation ----------------------------------------------------------------------------------
function Show-Row([string]$Label, [string]$Value, [string]$Note) {
    Write-Host ("  {0,-20}" -f $Label) -NoNewline
    Write-Host $Value -ForegroundColor Cyan -NoNewline
    if ($Note) { Write-Host "  ($Note)" -ForegroundColor DarkGray } else { Write-Host '' }
}
function State([bool]$Exists) { if ($Exists) { 'exists - will be updated' } else { 'new' } }
Write-Host ''
Write-Host $(if ($AgentOnly) { 'Agent-only deployment' } else { 'Deployment plan' }) -ForegroundColor Magenta
Show-Row 'Subscription' "$($sub.name) ($($sub.id))" $source['AZURE_SUBSCRIPTION_ID']
Show-Row 'Tenant' $sub.tenant
Show-Row 'Signed in as' $sub.user
if ($fromFile['AZURE_SUBSCRIPTION_ID'] -and $fromFile['AZURE_SUBSCRIPTION_ID'] -ne $current.id) {
    Write-Host "  [!] deployment.env subscription differs from the current az context ($($current.name))" -ForegroundColor Yellow
}
Show-Row 'Resource group' $resourceGroup "$($source['AZURE_RESOURCE_GROUP']), $(State $rgExists)"
Show-Row 'Location' $location $source['LOCATION']
Show-Row 'Foundry account' $foundryName "$($source['FOUNDRY_NAME']), $(State $foundryExists)"
Show-Row 'Foundry project' $projectName $source['PROJECT_NAME']
if ($fromFile['FOUNDRY_PROJECT_NAME'] -and $projectName -ne $fromFile['FOUNDRY_PROJECT_NAME']) {
    Write-Host "  [!] Project differs from deployment.env ($($fromFile['FOUNDRY_PROJECT_NAME'])): a new project + MCP connection is created in the same Foundry account; the old one stays until removed." -ForegroundColor Yellow
}
Show-Row 'Model' "$modelDeploymentName $modelVersion" 'GlobalStandard, capacity from main.bicep - default 500 = 500K TPM'
Show-Row 'Function App' $functionAppName "$($source['FUNCTION_APP_NAME']), $(State $functionExists)"
Show-Row 'Agent' $agentName "$($source['AGENT_NAME']), new version"
if ($fromFile['AGENT_NAME'] -and $agentName -ne $fromFile['AGENT_NAME']) {
    Write-Host "  [!] Agent name differs from deployment.env ($($fromFile['AGENT_NAME'])): a separate agent is created; the old one stays until removed." -ForegroundColor Yellow
}
if (-not $AgentOnly) {
    Show-Row 'Reporting mailbox' $(if ($reportingMailboxUpn) { $reportingMailboxUpn } else { '-' }) $mailboxNote
    Show-Row 'MCP key' '********' $keyNote
    # Fingerprint of function/ (first 12 hex chars of SHA-256) + whether this run uploads the code (README: 'Reading the deployment plan').
    Show-Row 'Function code' $codeHash.Substring(0, 12) $codeNote
}
if ($AgentOnly -and -not $foundryExists) { throw "Foundry account '$foundryName' not found in '$resourceGroup' - run a full deployment first." }
if (-not $Yes) {
    Write-Host ''
    $answer = Read-Host 'Continue with these settings? [y/N]'
    if ($answer -notmatch '^(y|yes)$') { Write-Host 'Aborted; nothing was changed.' -ForegroundColor Yellow; return }
}

if (-not $AgentOnly) {
az group create --name $resourceGroup --location $location --output none
if ($LASTEXITCODE -ne 0) { throw 'Resource group creation failed.' }
$deploymentName = 'phishing-triage-' + (Get-Date -Format 'yyyyMMddHHmmss')
$paramsPath = Join-Path ([IO.Path]::GetTempPath()) ('phishing-params-' + [guid]::NewGuid().ToString('N') + '.json')
$params = @{
  '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
  contentVersion = '1.0.0.0'
  parameters = @{
    location = @{ value = $location }
    foundryName = @{ value = $foundryName }
    functionAppName = @{ value = $functionAppName }
    modelDeploymentName = @{ value = $modelDeploymentName }
    projectName = @{ value = $projectName }
    modelVersion = @{ value = $modelVersion }
    mcpApiKey = @{ value = $apiKey }
    reportingMailboxUpn = @{ value = $reportingMailboxUpn }
  }
}
$paramsJson = $params | ConvertTo-Json -Depth 8
Set-Content -LiteralPath $paramsPath -Value $paramsJson -Encoding utf8
if ($PSVersionTable.Platform -eq 'Unix') {
    [System.IO.File]::SetUnixFileMode($paramsPath, [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite)
}
try {
    $outputsJson = az deployment group create --name $deploymentName --resource-group $resourceGroup --template-file (Join-Path $PSScriptRoot 'main.bicep') --parameters "@$paramsPath" --query properties.outputs --output json
    if ($LASTEXITCODE -ne 0) { throw 'Bicep deployment failed.' }
} finally {
    if (Test-Path $paramsPath) { Remove-Item -LiteralPath $paramsPath -Force }
}
$outputs = ($outputsJson -join "`n") | ConvertFrom-Json
$projectEndpoint = $outputs.projectEndpoint.value
$mcpEndpoint = $outputs.mcpEndpoint.value
$connectionName = $outputs.mcpConnectionName.value

# The executing user needs Azure AI User on the project to create the agent.
$projectId = $outputs.foundryProjectResourceId.value
$deployerPrincipalId = az ad signed-in-user show --query id --output tsv 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($deployerPrincipalId)) {
    Write-Warning 'Could not resolve the signed-in user (service principal login?). Skipping the Azure AI User assignment; the caller needs it on the project to create the agent.'
} else {
    az role assignment create --assignee-object-id $deployerPrincipalId --assignee-principal-type User --role '53ca6127-db72-4b80-b1b0-d745d6d5456d' --scope $projectId --output none  # Foundry User (formerly Azure AI User)
    if ($LASTEXITCODE -ne 0) { throw 'Azure AI User role assignment on the project failed.' }
    # Key Vault Secrets User on the vault, so later runs can reuse the MCP key instead of rotating it.
    $vaultId = az keyvault show --name $outputs.keyVaultName.value --query id --output tsv --only-show-errors
    az role assignment create --assignee-object-id $deployerPrincipalId --assignee-principal-type User --role '4633458b-17de-408a-b874-0445c86b69e6' --scope $vaultId --output none --only-show-errors
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Key Vault Secrets User assignment failed; the next run will rotate the MCP key.' }
}

# Flex Consumption: zip deploy with remote build (Oryx installs requirements.txt) - only when the code changed.
if ($deployCode) {
$zip = Join-Path ([IO.Path]::GetTempPath()) ('phishing-mcp-' + [guid]::NewGuid().ToString('N') + '.zip')
try {
    Compress-Archive -Path (Join-Path $PSScriptRoot 'function/*') -DestinationPath $zip
    az functionapp deployment source config-zip --resource-group $resourceGroup --name $functionAppName --src $zip --build-remote true --timeout 600 --output none
    if ($LASTEXITCODE -ne 0) { throw 'Function code deployment failed.' }
} finally {
    if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
}
} else {
    Write-Host 'Function code unchanged - skipped the zip deploy.' -ForegroundColor DarkGray
}

# The MCP extension authenticates with the mcp_extension system key (x-functions-key header).
# Set it to the same value as the Key Vault secret and the Foundry connection.
$keyAttempt = 0
while ($true) {
    $keyAttempt++
    az functionapp keys set --resource-group $resourceGroup --name $functionAppName --key-type systemKeys --key-name mcp_extension --key-value $apiKey --output none --only-show-errors
    if ($LASTEXITCODE -eq 0) { break }
    if ($keyAttempt -ge 6) { throw 'Could not set the mcp_extension system key.' }
    Write-Host 'Function host not ready for key update, retrying in 20s...'
    Start-Sleep -Seconds 20
}
Write-Host "Function principal ID: $($outputs.functionPrincipalId.value) (recorded in deployment.env; permissions.ps1 picks it up)"

# Document what was deployed (names/IDs only; the MCP key stays in Key Vault). Read by teardown.ps1 and re-runs.
$functionAppId = az ad sp show --id $outputs.functionPrincipalId.value --query appId --output tsv --only-show-errors 2>$null
$tenantId = az account show --query tenantId --output tsv --only-show-errors
$envLines = [ordered]@{
    DEPLOYED_AT_UTC               = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    AZURE_TENANT_ID               = $tenantId
    AZURE_SUBSCRIPTION_ID         = $subscriptionId
    AZURE_RESOURCE_GROUP          = $resourceGroup
    LOCATION                      = $outputs.location.value
    FOUNDRY_NAME                  = $outputs.foundryName.value
    FOUNDRY_PROJECT_NAME          = $outputs.projectName.value
    FOUNDRY_PROJECT_ENDPOINT      = $projectEndpoint
    FOUNDRY_PROJECT_RESOURCE_ID   = $outputs.foundryProjectResourceId.value
    MODEL_DEPLOYMENT              = $outputs.modelDeployment.value
    MODEL_VERSION                 = $modelVersion
    MCP_CONNECTION_NAME           = $connectionName
    AGENT_NAME                    = $agentName
    FUNCTION_APP_NAME             = $outputs.functionAppName.value
    FUNCTION_PLAN_NAME            = $outputs.planName.value
    MCP_ENDPOINT                  = $mcpEndpoint
    FUNCTION_PRINCIPAL_ID         = $outputs.functionPrincipalId.value
    FUNCTION_APP_ID               = $functionAppId
    KEY_VAULT_NAME                = $outputs.keyVaultName.value
    FUNCTION_CODE_SHA256          = $codeHash
    STORAGE_ACCOUNT_NAME          = $outputs.storageAccountName.value
    STORAGE_IDENTITY_NAME         = $outputs.storageIdentityName.value
    APP_INSIGHTS_NAME             = $outputs.appInsightsName.value
    REPORTING_MAILBOX_UPN         = $reportingMailboxUpn
    EXCHANGE_SCOPE_NAME           = 'PhishingTriage-ReportingMailbox'
    EXCHANGE_ROLE_ASSIGNMENT_NAME = 'PhishingTriage-ReportingMailbox-MailRead'
}
$content = @('# Written by deploy.ps1 - resource names of this deployment (no secrets). Used by teardown.ps1 and re-runs.')
$content += $envLines.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
Set-Content -LiteralPath $envFile -Value $content -Encoding utf8
Write-Host "Wrote $envFile" -ForegroundColor DarkGray
}

# Create (or add a new version of) the Foundry prompt agent wired to the MCP connection.
$instructions = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'agent-instructions.md') -Raw
$definition = @{
    kind = 'prompt'
    model = $modelDeploymentName
    instructions = $instructions
    tools = @(@{
        type = 'mcp'
        server_label = 'defender_phishing'
        server_url = $mcpEndpoint
        project_connection_id = $connectionName
        require_approval = 'never'   # all MCP tools are read-only
    })
}
$body = @{ description = 'Evidence-led Defender phishing email investigation agent.'; definition = $definition } | ConvertTo-Json -Depth 10

$attempt = 0
while ($true) {
    $attempt++
    $token = az account get-access-token --scope 'https://ai.azure.com/.default' --query accessToken --output tsv
    if ($LASTEXITCODE -ne 0) { throw 'Could not get a Foundry access token.' }
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
    try {
        $agent = Invoke-RestMethod -Method Post -Uri "$projectEndpoint/agents/$agentName/versions?api-version=v1" -Headers $headers -Body $body
        break
    } catch {
        $status = [int]$_.Exception.Response.StatusCode
        # New role assignments can take a few minutes to apply.
        if ($status -in 401, 403 -and $attempt -lt 12) {
            Write-Host "Agent creation returned $status (role assignment still propagating?), retrying in 30s..."
            Start-Sleep -Seconds 30
            continue
        }
        throw "Agent creation failed ($status): $($_.ErrorDetails.Message)"
    }
}

Write-Host "Agent '$($agent.name)' version $($agent.version) created in $projectEndpoint" -ForegroundColor Green
if (Test-Path -LiteralPath $envFile) {
    $lines = @(Get-Content -LiteralPath $envFile | Where-Object { $_ -notmatch '^AGENT_VERSION=' }) + "AGENT_VERSION=$($agent.version)"
    Set-Content -LiteralPath $envFile -Value $lines -Encoding utf8
}
Write-Host "MCP endpoint: $mcpEndpoint"
if (-not $AgentOnly) {
    Write-Host 'First deployment? Run ./permissions.ps1 (and optionally ./reporting-mailbox-access.ps1 -Apply) next - no IDs needed.' -ForegroundColor Yellow
    if ($mailboxSkipped) {
        Write-Host ''
        Write-Host 'Reminder: no reporting mailbox configured - list_reported_emails / get_reported_email return "not configured".' -ForegroundColor Yellow
        Write-Host '  Add it later without touching the Function settings by hand:' -ForegroundColor Yellow
        Write-Host '    ./deploy.ps1 -ReportingMailbox <reporting-mailbox-upn>' -ForegroundColor Yellow
        Write-Host '    ./reporting-mailbox-access.ps1 -Apply' -ForegroundColor Yellow
    } elseif ($reportingMailboxUpn -and $mailboxNote -ne 'kept from current app setting') {
        Write-Host "Reporting mailbox set to $reportingMailboxUpn - grant access with reporting-mailbox-access.ps1 -Apply (Exchange RBAC, 30 min-2 h to apply)." -ForegroundColor Yellow
    }
    Write-Host 'Note: MCP access uses a shared key (demo). For production switch to Entra ID auth - see README.' -ForegroundColor Yellow
}
