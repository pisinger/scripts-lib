# author: https://github.com/pisinger/scripts-lib/powershell
# blog: https://pisinger.github.io/posts/ingestion-into-sentinel-via-event-hub-made-simple

# required modules:
# Install-Module Az.EventHub -AllowClobber -Force -Scope CurrentUser
# Install-Module Az.Resources -AllowClobber -Force -Scope CurrentUser

#-------------------------------------------------------------
# steps overview
#	1 - create event hubs within namespace
#	2 - create custom table of type aux, basic or analytics -> make sure you have DCE linked to workspace
# 	3 - create DCR to send data into above custom table -> deploy custom template
# 	4 - Associate the DCR with the event hub (DCRA) -> deploy custom template
# 	5 - assign event hub receiver permission to DCR managed identity (role assignment)

#-------------------------------------------------------------
# variables
$location = "germanywestcentral"

$workspaceId = "/subscriptions/xxxxxxx/resourcegroups/xxxxxxx/providers/microsoft.operationalinsights/workspaces/xxxxxxx"
$dce_id = "/subscriptions/xxxxxxx/resourceGroups/xxxxxxx/providers/Microsoft.Insights/dataCollectionEndpoints/xxxxxxx"

$eventHubNamespaceId = "/subscriptions/xxxxxxx/resourceGroups/xxxxxxx/providers/Microsoft.EventHub/namespaces/xxxxxxx"
$eventHubNamespaceName = $eventHubNamespaceId.Split("/")[-1]

$workspaceName = $workspaceId.Split("/")[-1]
$resourceGroup = $workspaceId.Split("/")[-5]
$resourceGroupId = ($workspaceId.Split("/providers",2))[0]

#-----------------------------------------------------------
# map of data sources to create event hubs and corresponding tables in workspace

$dataMap = @(
    @{source="DataSource1"; partitions=10; totalRetentionInDays=30; plan="Analytics"},
    @{source="DataSource2"; partitions=10; totalRetentionInDays=30; plan="Basic"},
    @{source="DataSource3"; partitions=10; totalRetentionInDays=30; plan="Auxiliary"},
    @{source="DefenderStreamingApi"; partitions=4; totalRetentionInDays=30; plan="Auxiliary"}
)

#-----------------------------------------------------------
# 1 - create event hubs in existing namespace
# Install-Module az.eventhub

foreach ($item in $dataMap) {
	New-AzEventHub -ResourceGroupName $resourceGroup -NamespaceName $eventHubNamespaceName -Name $item.source -RetentionTimeInHour 72 -PartitionCount $item.partitions -CleanupPolicy Delete
}

#-------------------------------------------------------------
# 2 - create custom table of type aux in desired workspace
# depending on your transformations you may want to adjust the table schema, can also be done afterwards
# reserved column names: id, _ResourceId, _SubscriptionId, TenantId, Type, UniqueId, Title

$tableParams = @'
{
    "properties": {
		"plan": "var_plan",
		"totalRetentionInDays": var_retention,
        "schema": {
            "name": "var_tableName",
            "columns": [
                {
                    "name": "TimeGenerated",
                    "type": "datetime",
                    "description": "The time at which the data was ingested."
                },
                {
                    "name": "RawData",
                    "type": "string",
                    "description": "Body of the event."
                }
            ]
        }
    }
}
'@

foreach ($item in $dataMap) {
	
	$table = $tableParams -replace "var_tableName", $($item.source + "_CL")
	$table = $table -replace "var_retention", $item.totalRetentionInDays
	$table = $table -replace "var_plan", $item.plan

    Invoke-AzRestMethod -Path $($workspaceId + "/tables/" + $item.source + "_CL" + "?api-version=2023-01-01-preview") -Method PUT -payload $table
}

#-------------------------------------------------------------
# 3 - create dedicated DCR per source for EventHubStream to send data into above custom tables
# DCR and DCE needs to be in same region as the workspace
# DCE needs to be created before going with below ARM template
# when using AMPLS, create the DCE in desired region and then associate with AMPLS scope

# NOTE: The stream must named as Custom-MyEventHubStream

$dcrParams = @'
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "dataCollectionRuleName": {
            "type": "string",
            "metadata": {
                "description": "Specifies the name of the data collection Rule to create."
            },
            "defaultValue": "var_dataCollectionRuleName"
        },
        "workspaceResourceId": {
            "type": "string",
            "metadata": {
                "description": "Specifies the Azure resource ID of the Log Analytics workspace to use."
            },
            "defaultValue": "var_workspaceId"
        },
        "endpointResourceId": {
            "type": "string",
            "metadata": {
                "description": "Specifies the Azure resource ID of the data collection endpoint to use."
            },
            "defaultValue": "var_endpointResourceId"
        },
        "tableName": {
            "type": "string",
            "metadata": {
                "description": "Specifies the name of the table in the workspace."
            },
            "defaultValue": "var_tableName"
        },
        "consumerGroup": {
            "type": "string",
            "metadata": {
                "description": "Specifies the consumer group of event hub."
            },
            "defaultValue": "$Default"
        },
        "location": {
            "type": "string",
            "metadata": {
                "description": "Specifies the location of the data collection rule."
            },
            "defaultValue": "var_location"
        }
    },
    "resources": [
        {
            "type": "Microsoft.Insights/dataCollectionRules",
            "name": "[parameters('dataCollectionRuleName')]",
            "location": "[parameters('location')]",
            "apiVersion": "2022-06-01",
            "identity": {
                "type": "systemAssigned"
            },
            "properties": {
                "dataCollectionEndpointId": "[parameters('endpointResourceId')]",
                "streamDeclarations": {
                    "Custom-MyEventHubStream": {
                        "columns": [
                            {
                                "name": "TimeGenerated",
                                "type": "datetime"
                            },
                            {
                                "name": "RawData",
                                "type": "string"
                            },
                            {
                                "name": "Properties",
                                "type": "dynamic"
                            }
                        ]
                    }
                },
                "dataSources": {
                    "dataImports": {
                        "eventHub": {
                            "consumerGroup": "[parameters('consumerGroup')]",
                            "stream": "Custom-MyEventHubStream",
                            "name": "myEventHubDataSource1"
                        }
                    }
                },
                "destinations": {
                    "logAnalytics": [
                        {
                            "workspaceResourceId": "[parameters('workspaceResourceId')]",
                            "name": "MyDestinationWorkspace"
                        }
                    ]
                },
                "dataFlows": [
                    {
                        "streams": [
                            "Custom-MyEventHubStream"
                        ],
                        "destinations": [
                            "MyDestinationWorkspace"
                        ],
                        "outputStream": "[concat('Custom-', parameters('tableName'))]"
                    }
                ]
            }
        },
        {
            "type": "Microsoft.Insights/diagnosticSettings",
            "apiVersion": "2021-05-01-preview",
            "scope": "[format('Microsoft.Insights/dataCollectionRules/{0}', parameters('dataCollectionRuleName'))]",
            "name": "[format('dcr-diagnostics-{0}', parameters('dataCollectionRuleName'))]",
            "dependsOn": [
                "[resourceId('Microsoft.Insights/dataCollectionRules', parameters('dataCollectionRuleName'))]"
            ],
            "properties": {
                "workspaceId": "[parameters('workspaceResourceId')]",
                "logs": [
                    {
                        "categoryGroup": "allLogs",
                        "enabled": true,
                        "retentionPolicy": {
                            "enabled": false,
                            "days": 0
                        }
                    }
                ]
            }
        }
    ]
}
'@

foreach ($item in $dataMap) {
	
    $dcrName = ("EVH-" + $($item.source + "_" + $workspaceName).ToLower())
	
	$dcrTemplate = $dcrParams -replace "var_tableName", $($item.source + "_CL")
	$dcrTemplate = $dcrTemplate -replace "var_endpointResourceId", $dce_id
    $dcrTemplate = $dcrTemplate -replace "var_workspaceId", $workspaceId
    $dcrTemplate = $dcrTemplate -replace "var_location", $location
    $dcrTemplate = $dcrTemplate -replace "var_dataCollectionRuleName", $dcrName

    $TemplateHashTable = $dcrTemplate | ConvertFrom-Json -AsHashtable
    New-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateObject $TemplateHashTable -DeploymentName $dcrName
}

#-------------------------------------------------------------
# 4 - Associate the data collection rule with the event hub (DCRA)

$dcrAssociateParams = @'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "eventHubResourceID": {
      "type": "string",
      "metadata": {
        "description": "Specifies the Azure resource ID of the event hub to use."
      },
      "defaultValue": "var_EventHubResourceID"
    },
    "associationName": {
      "type": "string",
      "metadata": {
        "description": "The name of the association."
      },
      "defaultValue": "var_associationName"
    },
    "dataCollectionRuleID": {
      "type": "string",
      "metadata": {
        "description": "The resource ID of the data collection rule."
      },
      "defaultValue": "var_dataCollectionRuleID"
    }
  },
  "resources": [
    {
      "type": "Microsoft.Insights/dataCollectionRuleAssociations",
      "apiVersion": "2021-09-01-preview",
      "scope": "[parameters('eventHubResourceId')]",
      "name": "[parameters('associationName')]",
      "properties": {
        "description": "Association of data collection rule. Deleting this association will break the data collection for this event hub.",
        "dataCollectionRuleId": "[parameters('dataCollectionRuleId')]"
      }
    }
  ]
}
'@

foreach ($item in $dataMap) {
	
	$dcrName = ("EVH-" + $($item.source + "_" + $workspaceName).ToLower())
    $dcrId = $($resourceGroupId + "/providers/Microsoft.Insights/dataCollectionRules/" + $dcrName)
    $dcrAssocName = ("EVH-dcr-assoc-" + $item.source + "_" + $workspaceName).ToLower()

	$associateTemplate = $dcrAssociateParams -replace "var_EventHubResourceID", $($eventHubNamespaceId + "/eventhubs/" + $item.source)
    $associateTemplate = $associateTemplate -replace "var_dataCollectionRuleID", $dcrId
    $associateTemplate = $associateTemplate -replace "var_associationName", $dcrAssocName

    $TemplateHashTable = $associateTemplate | ConvertFrom-Json -AsHashtable
    New-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateObject $TemplateHashTable -DeploymentName $dcrAssocName
}

#-------------------------------------------------------------
# 5 - assign event hub receiver permission to DCR managed identity (role assignment)

foreach ($item in $dataMap) {
	
    $dcrName = ("EVH-" + $($item.source + "_" + $workspaceName).ToLower())
	$EventHubId = $($eventHubNamespaceId + "/eventhubs/" + $item.source)

	# Get the DCR managed identity
	$dcr = Get-AzResource -ResourceGroupName $resourceGroup -ResourceType "Microsoft.Insights/dataCollectionRules" -ResourceName $dcrName
	$principalId = $dcr.Identity.PrincipalId

	# Assign the Event Hub Data Receiver role to the DCR managed identity
	New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Azure Event Hubs Data Receiver" -Scope $EventHubId
}
