// Consumption Logic App that runs the phishing triage agent for one Defender XDR incident ID
// (manual HTTP trigger) and parses the agent's JSON incident-update proposal. Read-only: it does not
// change the incident. Its managed identity gets Azure AI User on the Foundry project to invoke the agent.
targetScope = 'resourceGroup'

param location string = resourceGroup().location
param logicAppName string
param foundryName string
param projectName string = 'defender-agents'
param agentName string = 'ps-phishing-triage'

var azureAiUserRoleId = '53ca6127-db72-4b80-b1b0-d745d6d5456d'

resource foundry 'Microsoft.CognitiveServices/accounts@2025-06-01' existing = {
  name: foundryName
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' existing = {
  parent: foundry
  name: projectName
}

resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('workflow.json')
    parameters: {
      projectEndpoint: { value: 'https://${foundryName}.services.ai.azure.com/api/projects/${projectName}' }
      agentName: { value: agentName }
    }
  }
}

resource agentInvoker 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(project.id, logicApp.id, azureAiUserRoleId)
  scope: project
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', azureAiUserRoleId)
    principalId: logicApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output logicAppName string = logicApp.name
output principalId string = logicApp.identity.principalId
