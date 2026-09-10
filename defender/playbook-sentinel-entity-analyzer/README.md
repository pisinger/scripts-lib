# Sentinel Entity Analyzer playbook

This workspace contains an Azure Resource Manager template for a Microsoft Sentinel incident-triggered Logic App. It analyzes supported Account, URL, and DNS entities with the Sentinel MCP Entity Analyzer, then posts one summarized incident comment through a Logic Apps Agent action.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpisinger%2Fscripts-lib%2Fmain%2Fdefender%2Fplaybook-sentinel-entity-analyzer%2Fsentinel-entity-analyzer-agent-summary.template.json)

## Files

| File | Purpose |
| --- | --- |
| `sentinel-entity-analyzer-agent-summary.template.json` | ARM deployment template for the playbook, connections, managed identity, and workflow definition |
| `sentinel-entity-analyzer-agent-summary.parameters.json` | Example deployment parameters |
| `assign-permissions.sh` | Idempotently assigns the playbook identity's required permissions |

The template deploys the workflow disabled by default. It uses sequential entity analysis (`entityConcurrency: 1`) and reports IP entities as skipped because the analyzer does not support IP addresses.

## Deploy

1. Replace `REPLACE-WITH-WORKSPACE-CUSTOMERID-GUID` in `sentinel-entity-analyzer-agent-summary.parameters.json` with the Sentinel workspace **customer ID** GUID. This is not the workspace ARM resource ID.
2. Deploy the template to the target resource group:

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file sentinel-entity-analyzer-agent-summary.template.json \
  --parameters @sentinel-entity-analyzer-agent-summary.parameters.json
```

3. Run the playbook once while it is disabled, inspect the result, then change `workflowState` to `Enabled` and configure the Sentinel automation rule.

## Permissions

After deployment, grant permissions to the Logic App's system-assigned managed identity. Use either its object ID or let the script look it up by Logic App name:

```bash
./assign-permissions.sh \
  --workspace-resource-id "/subscriptions/<subscription>/resourceGroups/<workspace-rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>" \
  --principal-id <managed-identity-object-id> \
  --dry-run
```

Remove `--dry-run` to apply the changes. The script assigns Microsoft Sentinel Responder and the Entra Security Reader directory role. Security Copilot Contributor remains a manual prerequisite in the Security Copilot portal.

## Prerequisites

- Azure CLI with access to the target subscription and resource group.
- A Sentinel-enabled Log Analytics workspace onboarded to the Defender portal and Sentinel data lake.
- Sentinel SOAR Essentials installed.
- Security Copilot provisioned and authorized for Entity Analyzer use.
- A region where the `sentinelmcp` connector is available.
