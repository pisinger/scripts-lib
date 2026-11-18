targetScope = 'resourceGroup'

@description('Azure region for Foundry and the MCP Function App.')
param location string = 'swedencentral'
@description('Globally unique, lowercase 3-24 character Foundry resource name.')
param foundryName string
@description('Globally unique Function App name (lowercase, 2-60 characters).')
param functionAppName string
@description('Name of the Foundry project.')
param projectName string = 'defender-agents'
@description('Model deployment name exposed to the project.')
param modelDeploymentName string = 'gpt-5.6-luna'
@description('Model name as exposed in the regional catalog. Verify availability before deployment.')
param modelName string = 'gpt-5.6-luna'
@description('Exact model version from the Sweden Central catalog.')
param modelVersion string
@description('Capacity units for the selected deployment SKU (GlobalStandard: 1 unit = 1,000 TPM). Default 500 = 500K TPM.')
@minValue(1)
param modelCapacity int = 500
@description('MCP key: stored in Key Vault (operator copy) and the Foundry connection; deploy.ps1 sets it as the Function mcp_extension system key. Supply securely; never commit it.')
@minLength(43)
@maxLength(256)
@secure()
param mcpApiKey string
@description('Optional dedicated Defender user-reported-message mailbox UPN. Leave blank to keep reporting-mailbox retrieval disabled.')
param reportingMailboxUpn string = ''
@description('Name of the project connection that holds the MCP API key.')
param mcpConnectionName string = 'phishing-triage-mcp'

var suffix = uniqueString(subscription().id, resourceGroup().id, foundryName)
var storageName = take('stphish${suffix}', 24)
var vaultName = take('kv-phish-${suffix}', 24)
var appInsightsName = 'appi-phish-${suffix}'
var planName = 'plan-flex-phish-${suffix}'
var deploymentContainerName = 'app-package'
// Azure Functions MCP extension endpoint (Streamable HTTP); auth = mcp_extension system key.
var mcpEndpoint = 'https://${function.properties.defaultHostName}/runtime/webhooks/mcp'

resource foundry 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: foundryName
  location: location
  kind: 'AIServices'
  sku: { name: 'S0' }
  properties: {
    customSubDomainName: foundryName
    disableLocalAuth: true
    allowProjectManagement: true
    publicNetworkAccess: 'Enabled'
  }
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' = {
  parent: foundry
  name: projectName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Defender Agents'
    description: 'Agents for Defender investigations (phishing triage and more).'
  }
}

resource model 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = {
  parent: foundry
  name: modelDeploymentName
  sku: { name: 'GlobalStandard', capacity: modelCapacity }
  properties: {
    model: {
      format: 'OpenAI'
      name: modelName
      version: modelVersion
    }
    versionUpgradeOption: 'NoAutoUpgrade'
  }
  // Child operations on the same account conflict (RequestConflict) when run in parallel.
  dependsOn: [ project ]
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Enabled'
  }
  resource blobServices 'blobServices' = {
    name: 'default'
    resource deploymentContainer 'containers' = {
      name: deploymentContainerName
      properties: { publicAccess: 'None' }
    }
  }
}

// Keep host storage authentication on a dedicated user-assigned identity so the
// Function app never receives the storage account key in its settings.
resource storageIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-phish-storage-${suffix}'
  location: location
}

resource storageBlobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, storageIdentity.id, 'storage-blob-data-owner')
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: storageIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageQueueContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, storageIdentity.id, 'storage-queue-data-contributor')
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '974c5e8b-45b9-4653-ba55-5f855dd0fb88')
    principalId: storageIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageTableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, storageIdentity.id, 'storage-table-data-contributor')
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
    principalId: storageIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Flex Consumption: Linux Consumption (Y1) does not accept zip deployment from the Azure CLI.
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  kind: 'functionapp'
  sku: { tier: 'FlexConsumption', name: 'FC1' }
  properties: { reserved: true }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: { Application_Type: 'web' }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    publicNetworkAccess: 'Enabled'
  }
}

resource apiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'mcp-api-key'
  properties: { value: mcpApiKey }
}

resource function 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned, UserAssigned'
    userAssignedIdentities: { '${storageIdentity.id}': {} }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: storageIdentity.id
          }
        }
      }
      scaleAndConcurrency: { maximumInstanceCount: 40, instanceMemoryMB: 2048 }
      runtime: { name: 'python', version: '3.12' }
    }
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'AzureWebJobsStorage__clientId', value: storageIdentity.properties.clientId }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights.properties.ConnectionString }
        { name: 'GRAPH_API_BASE', value: 'https://graph.microsoft.com/beta' }
        { name: 'REPORTING_MAILBOX_UPN', value: reportingMailboxUpn }
      ]
    }
  }
  dependsOn: [ apiKeySecret, storageBlobOwner, storageQueueContributor, storageTableContributor, storage::blobServices::deploymentContainer ]
}

// Custom-keys connection: Foundry sends the key as x-functions-key (the MCP extension's system key,
// set to the same value by deploy.ps1). The key never leaves secure parameters.
// DEMO ONLY. Production: Entra ID instead of a key - Function built-in auth (Entra app registration,
// Application ID URI as audience), webhookAuthorizationLevel=Anonymous, only the project MI allowed, and an
// MCP connection with project managed identity auth (audience = Application ID URI). See README.
resource mcpConnection 'Microsoft.CognitiveServices/accounts/projects/connections@2025-06-01' = {
  parent: project
  name: mcpConnectionName
  properties: {
    category: 'CustomKeys'
    authType: 'CustomKeys'
    target: mcpEndpoint
    isSharedToAll: false
    credentials: { keys: { 'x-functions-key': mcpApiKey } }
    metadata: { purpose: 'phishing-triage-mcp' }
  }
}

output foundryEndpoint string = foundry.properties.endpoint
output foundryProjectResourceId string = project.id
output modelDeployment string = model.name
output mcpEndpoint string = mcpEndpoint
output projectEndpoint string = 'https://${foundryName}.services.ai.azure.com/api/projects/${projectName}'
output mcpConnectionName string = mcpConnection.name
output functionPrincipalId string = function.identity.principalId
output keyVaultName string = vault.name
output location string = location
output foundryName string = foundry.name
output projectName string = project.name
output functionAppName string = function.name
output storageAccountName string = storage.name
output storageIdentityName string = storageIdentity.name
output appInsightsName string = insights.name
output planName string = plan.name
