# define variables
$ResourceGroup = "sampleDnsResourceGroup"
$location = "swedencentral"

$DnsDomainListName = "sampleDnsResolverDomainListWildcard"
$DnsResolverPolicy = "sampleDnsResolverPolicy"
$DnsSecurityRule = "sampleAuditAllRequests"

$diagnosticSettingName = "sampleDnsResolverPolicyDiagnosticSetting"
$workspaceId = "/subscriptions/xxxxxxxx/resourcegroups/xxxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxxx"

$vnet = "/subscriptions/xxxxxxxx/resourceGroups/xxxxxxxx/providers/Microsoft.Network/virtualNetworks/xxxxxxxx"

# create resource group
az group create --name $ResourceGroup --location $location

# create dns resolver policy
$resolverPolicyId = $(az dns-resolver policy create --resource-group $ResourceGroup --dns-resolver-policy-name $DnsResolverPolicy --location $location --query id --output tsv)

# create domain list - wildcard to monitor/audit all domains
$DnsDomainListId = $(az dns-resolver domain-list create --resource-group $ResourceGroup --dns-resolver-domain-list-name $DnsDomainListName --location $location --domains "[.]" --query id --output tsv)
$DnsDomainListName = $("[{id:" + $DnsDomainListId + "}]")

# create and attach dns security rule mapped to domainLists to above dns resolver policy
az dns-resolver policy dns-security-rule create --resource-group $ResourceGroup --policy-name $DnsResolverPolicy --dns-security-rule-name $DnsSecurityRule --location $location --priority 100 --action "{action-type:Allow}" --domain-lists $DnsDomainListName --rule-state Enabled

# link your vnets
$vnet = $("[{id:" + $vnet + "}]")
az dns-resolver policy vnet-link create --resource-group $ResourceGroup  --policy-name $DnsResolverPolicy --dns-resolver-policy-virtual-network-link-name "sampleVirtualNetworkLink1" --location $location --virtual-network $vnet

# create diag settings
az monitor diagnostic-settings create --name $diagnosticSettingName --resource $resolverPolicyId --logs '[{"category":"DnsResponse","enabled":true}]' --workspace $workspaceId

# set DNSQueryLogs to basic tier
$resourceGroup = $workspaceId -match "/resourcegroups/([^/]+)/" | Out-Null; $resourceGroup = $matches[1]
$workspaceName = $workspaceId -match "/workspaces/([^/]+)$" | Out-Null; $workspaceName = $matches[1]
az monitor log-analytics workspace table update --resource-group $ResourceGroup --workspace-name $workspaceName --name "DNSQueryLogs" --plan Basic --retention-time -1
