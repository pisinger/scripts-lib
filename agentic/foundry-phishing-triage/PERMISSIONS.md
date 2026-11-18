# Required permissions for the operator

This page lists the roles the person running the scripts needs. It does not cover the permissions of the deployed Function: those are the Graph app roles that `permissions.ps1` assigns, listed in the README.

All scripts use the current `az login` session, and `reporting-mailbox-access.ps1` also uses an Exchange Online session. Each script needs different rights. In practice, an Azure owner runs `deploy.ps1` and an Entra / Exchange administrator runs the two grant scripts.

## Summary

| Script | Azure RBAC | Entra ID role | Exchange Online |
|---|---|---|---|
| `deploy.ps1` | **Owner** on the resource group (or Contributor + Role Based Access Control Administrator); subscription-level rights only to create the resource group and register providers | none (default user rights) | none |
| `deploy.ps1 -AgentOnly` | **Foundry User** on the project (assigned by the first full deploy) | none | none |
| `permissions.ps1` | none | **Privileged Role Administrator** | none |
| `reporting-mailbox-access.ps1` | none | **Exchange Administrator** (or Organization Management in Exchange) | Organization Management |
| `teardown.ps1` | **Owner** on the resource group + purge rights at subscription scope | **Agent ID Administrator** + **Cloud Application Administrator** for the Entra agent cleanup | Organization Management for `-IncludeExchange` |

Use PIM to activate these roles for the run only; none of them is needed afterwards.

## `deploy.ps1`

| What the script does | Needed permission |
|---|---|
| `az group create` when the resource group does not exist | `Microsoft.Resources/subscriptions/resourceGroups/write` on the subscription (Contributor on the subscription). If someone pre-creates the resource group, Owner on the resource group is enough. |
| Bicep: storage, Flex Consumption plan, Function App, Key Vault, App Insights, Foundry account, project, model deployment, project connection | Contributor on the resource group |
| Bicep: three role assignments for the storage user-assigned identity (Storage Blob Data Owner, Storage Queue Data Contributor, Storage Table Data Contributor) | `Microsoft.Authorization/roleAssignments/write`: Owner, User Access Administrator or Role Based Access Control Administrator on the resource group |
| Assigns itself **Foundry User** (`53ca6127-…`) on the project, to create the agent | same as above |
| Assigns itself **Key Vault Secrets User** (`4633458b-…`) on the vault, to reuse the MCP key on re-runs | same as above |
| Zip deploy with remote build, `az functionapp keys set` (`mcp_extension` system key), app settings | Contributor (Website Contributor) on the Function App |
| `az ad signed-in-user show`, `az ad sp show` (Function identity) | default Entra user rights |
| Creates the agent version (`POST {project}/agents/{name}/versions`) | Foundry User on the project (see above; can take a few minutes to propagate, so the script retries) |

**Prerequisites at subscription level:**

- **Resource providers:** `Microsoft.Web`, `Microsoft.CognitiveServices`, `Microsoft.KeyVault`, `Microsoft.Storage`, `Microsoft.Insights`, `Microsoft.OperationalInsights` and `Microsoft.ManagedIdentity` must be registered. Registering them needs Contributor on the subscription. They are usually registered already.
- **Model quota:** the `gpt-5.6-luna` deployment (500K TPM, GlobalStandard) needs quota in the region. Quota is not a role. Check it in the Foundry portal under *Quota*.

**Least privilege:** use Contributor plus **Role Based Access Control Administrator** on the resource group, with a condition that limits the assignable roles to the five roles above. That replaces Owner.

## `permissions.ps1`

The script assigns Microsoft Graph application roles to the Function managed identity (`POST /servicePrincipals/{id}/appRoleAssignedTo`), and removes roles left on the legacy Defender APIs.

- **Entra role:** **Privileged Role Administrator**. This is the least privileged built-in role that can grant **Microsoft Graph** app roles. Application Administrator and Cloud Application Administrator can assign app roles of other APIs, but not Microsoft Graph's.
- **Token:** the Azure CLI token used by `az rest` carries the needed delegated scope (`Directory.AccessAsUser.All`), so no extra consent is needed.

Doc: [Grant an appRoleAssignment for a service principal](https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignedto#permissions)

## `reporting-mailbox-access.ps1`

The script creates the Exchange service principal pointer, a management scope and an `Application Mail.Read` role assignment scoped to the reporting mailbox (Exchange RBAC for Applications).

- **Exchange:** **Exchange Administrator** in Entra ID, or membership in the Exchange **Organization Management** role group. Organization Management holds the delegating assignment for the application roles.
- **Entra:** the `az rest` lookups of the Function service principal and its Graph app roles need only default user rights.
- **Sign-in:** interactive, with automatic device-code fallback (`-UseDeviceCode` or `EXO_USE_DEVICE_CODE=1` to force device code).

Doc: [RBAC for Applications in Exchange Online](https://learn.microsoft.com/exchange/permissions-exo/application-rbac#requirements)

## `teardown.ps1`

| Step | Needed permission |
|---|---|
| Delete the resource group | Owner or Contributor on the resource group |
| Purge the soft-deleted Key Vault (`az keyvault purge`) | `Microsoft.KeyVault/locations/deletedVaults/purge/action`. The deleted vault lives at subscription scope, so a resource-group role is not enough: use Key Vault Contributor or Contributor on the subscription. |
| Purge the soft-deleted Foundry account (`az cognitiveservices account purge`) | `Microsoft.CognitiveServices/locations/resourceGroups/deletedAccounts/delete` at subscription scope (Contributor or Cognitive Services Contributor on the subscription) |
| Delete the Entra Agent ID objects (agent identity, blueprint principal, blueprint application) | **Agent ID Administrator** for agent identities and blueprint principals; **Cloud Application Administrator** (or Application Administrator) for the blueprint application. Foundry creates these objects, so the operator is not their owner. |
| `-PurgeEntra` (permanent delete from `deletedItems`) | same Entra roles |
| `-IncludeExchange` (remove role assignment, scope, service principal pointer) | Exchange Administrator / Organization Management |

Without the purge rights the script warns and continues. The soft-deleted Key Vault and Foundry account are then purged automatically after their retention period (Key Vault 90 days by default, Foundry 48 hours), but until then they keep the names and the model quota taken.

Docs: [Delete and restore agent identity objects](https://learn.microsoft.com/entra/agent-id/howto-delete-agent-identity) · [Key Vault soft-delete](https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview)

## Tenant prerequisites (not roles)

- **Defender for Office 365 Plan 2:** needed for the Advanced Hunting email tables (`EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, …) and analyzedEmails.
