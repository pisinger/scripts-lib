# Deploys the Consumption Logic App that runs the triage agent for one incident ID (manual trigger).
#   ./deploy-logicapp.ps1          names from deployment.env (run ./deploy.ps1 first)
#   ./deploy-logicapp.ps1 -Yes     skip the confirmation prompt
#   ./deploy-logicapp.ps1 -AgentName <name>   point the Logic App at another agent (default: AGENT_NAME in deployment.env)
# deploy.ps1 calls this automatically when the agent or project name changes and LOGIC_APP_NAME is set.
# New agent versions need no redeploy: the Logic App calls the agent's current version.
# Test: Logic App > Overview > Run with payload > Headers: incidentId = 12345 (or Queries, or body {"incidentId": "12345"}); read the 'Result' action output.
# Read-only: the Logic App only invokes the agent and parses its JSON proposal; it does not update the incident.
param(
    [switch]$Yes,
    [string]$AgentName,
    [string]$ProjectName
)
$ErrorActionPreference = 'Stop'

$envFile = Join-Path $PSScriptRoot 'deployment.env'
if (-not (Test-Path -LiteralPath $envFile)) { throw 'deployment.env not found - run ./deploy.ps1 first.' }
$cfg = @{}
foreach ($line in Get-Content -LiteralPath $envFile) {
    if ($line -match '^\s*([A-Z_]+)=(.*)$') { $cfg[$Matches[1]] = $Matches[2].Trim() }
}

$subscriptionId = $cfg['AZURE_SUBSCRIPTION_ID']
$resourceGroup  = $cfg['AZURE_RESOURCE_GROUP']
$foundryName    = $cfg['FOUNDRY_NAME']
$projectName    = if ($ProjectName) { $ProjectName } elseif ($cfg['FOUNDRY_PROJECT_NAME']) { $cfg['FOUNDRY_PROJECT_NAME'] } else { 'defender-agents' }
$agentName      = if ($AgentName) { $AgentName } elseif ($cfg['AGENT_NAME']) { $cfg['AGENT_NAME'] } else { 'ps-phishing-triage' }
# Same suffix as the Foundry account (fdyphish<suffix>), so names stay paired.
$logicAppName   = "ps-logic-phish-triage-$($foundryName -replace '^fdyphish', '')"

az account set --subscription $subscriptionId --only-show-errors
if ($LASTEXITCODE -ne 0) { throw "az account set failed for subscription $subscriptionId." }

Write-Host 'Logic App deployment' -ForegroundColor Magenta
Write-Host "  Subscription    $subscriptionId"
Write-Host "  Resource group  $resourceGroup"
Write-Host "  Logic App       $logicAppName  (Consumption, manual trigger)"
Write-Host "  Invokes agent   $agentName  in  $foundryName/$projectName"
Write-Host "  Role            Azure AI User on the project for the Logic App managed identity"
if (-not $Yes) {
    $answer = Read-Host 'Continue? [y/N]'
    if ($answer -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; return }
}

az deployment group create `
    --resource-group $resourceGroup `
    --name "logicapp-$(Get-Date -Format yyyyMMddHHmmss)" `
    --template-file (Join-Path $PSScriptRoot 'logicapp/logicapp.bicep') `
    --parameters logicAppName=$logicAppName foundryName=$foundryName projectName=$projectName agentName=$agentName `
    --output none --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'Logic App deployment failed.' }

$lines = @(Get-Content -LiteralPath $envFile | Where-Object { $_ -notmatch '^LOGIC_APP_NAME=' }) + "LOGIC_APP_NAME=$logicAppName"
Set-Content -LiteralPath $envFile -Value $lines -Encoding utf8

Write-Host "Logic App '$logicAppName' deployed." -ForegroundColor Green
Write-Host 'Test: Azure portal > Logic App > Overview > Run with payload > Headers: incidentId = 12345' -ForegroundColor Yellow
Write-Host 'The role assignment can take a few minutes to apply; a 401/403 on Start_agent_run right after deploy is expected.' -ForegroundColor Yellow
