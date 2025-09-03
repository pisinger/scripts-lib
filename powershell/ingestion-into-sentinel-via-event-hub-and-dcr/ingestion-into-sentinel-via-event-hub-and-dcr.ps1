
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
param(
	$location = "germanywestcentral",
	
	[Parameter(Mandatory=$True)]
	$workspaceId,
	
	[Parameter(Mandatory=$True)]
	$dce_id,
	
	[Parameter(Mandatory=$True)]
	$eventHubNamespaceId,

    $resourceSuffix = "team123"
)

$eventHubNamespaceName = $eventHubNamespaceId.Split("/")[-1]
#$workspaceName = $workspaceId.Split("/")[-1]
$resourceGroup = $workspaceId.Split("/")[-5]
$resourceGroupId = ($workspaceId.Split("/providers",2))[0]

#-----------------------------------------------------------
# map of data sources to create event hubs and corresponding tables in workspace including DCR

$dataMap = @{
    "NetworkLogs" = @{
        name = "NetworkLogs";
        partitions = 20;
        plan = "Auxiliary";
        totalRetentionInDays = 30;
        columns = @(
            @{ name = "TimeGenerated"; type = "datetime"; description = "The time at which the data was ingested." },
            @{ name = "RawData"; type = "string"; description = "Body of the event." },
            @{ name = "Column1"; type = "string"; description = "Custom column 1." }
        )
    };
    "SecurityEvents" = @{
        name = "SecurityEvents";
        partitions = 20;
        plan = "Auxiliary";
        totalRetentionInDays = 30;
        columns = @(
            @{ name = "TimeGenerated"; type = "datetime"; description = "The time at which the data was ingested." },
            @{ name = "RawData"; type = "string"; description = "Body of the event." },
            @{ name = "ColumnA"; type = "int"; description = "Custom column A." },
            @{ name = "ColumnB"; type = "string"; description = "Custom column B." }
        )
    };
    "ProxyLogs" = @{
        name = "ProxyLogs";
        partitions = 20;
        plan = "Auxiliary";
        totalRetentionInDays = 30;
        columns = @(
            @{ name = "TimeGenerated"; type = "datetime"; description = "The time at which the data was ingested." },
            @{ name = "RawData"; type = "string"; description = "Body of the event." },
            @{ name = "ColumnA"; type = "int"; description = "Custom column A." },
            @{ name = "ColumnB"; type = "string"; description = "Custom column B." }
        )
    }
}

#-----------------------------------------------------------
# 1 - create event hubs in existing namespace
# Install-Module az.eventhub

foreach ($table in $dataMap.keys) {
    $item = $datamap[$table]

    IF (-not$(Get-AzEventHub -ResourceGroupName $resourceGroup -NamespaceName $eventHubNamespaceName -Name $item.name -ErrorAction SilentlyContinue) ) {
        Write-Host "Creating event hub: " $item.name -ForegroundColor Cyan
        New-AzEventHub -ResourceGroupName $resourceGroup -NamespaceName $eventHubNamespaceName -Name $item.name -RetentionTimeInHour 72 -PartitionCount $item.partitions -CleanupPolicy Delete
    } 
    ELSE {
        Write-Host "Event hub already exists:" $item.name -ForegroundColor Green
        continue
    }
}

#-------------------------------------------------------------
# 2 - create custom table of type aux in desired workspace
# depending on your transformations you may want to adjust the table schema, can also be done afterwards
# reserved column names: id, _ResourceId, _SubscriptionId, TenantId, Type, UniqueId, Title

foreach ($table in $dataMap.keys) {
    $item = $datamap[$table]

    # create dynamic schema per table
    $columnsJson = $item.columns | ForEach-Object {
        @{
            name = $_.name;
            type = $_.type;
            description = $_.description
        }
    }

    $tableParams = @{
        properties = @{
            plan = $item.plan;
            totalRetentionInDays = $item.retention;
            schema = @{
                name = $($item.name + "_CL");
                columns = $columnsJson
            }
        }
    }

    $jsonPayload = $tableParams | ConvertTo-Json -Depth 5    

    Try {
        $tableExists = Invoke-AzRestMethod -Path $($workspaceId + "/tables/" + $item.name + "_CL" + "?api-version=2023-01-01-preview") -Method "GET" -ErrorAction Stop

        IF( $tableExists.StatusCode -like "2*" ) {
            Write-Host $("Update existing workspace table: " + $item.name) -ForegroundColor Magenta -NoNewline
            $response = Invoke-AzRestMethod -Path $($workspaceId + "/tables/" + $item.name + "_CL" + "?api-version=2023-01-01-preview") -Method "PATCH" -payload $jsonPayload -ErrorAction Stop
            
        }
        ELSE {
             Write-Host $("Creating new workspace table: " + $item.name) -ForegroundColor Cyan -NoNewline
            $response = Invoke-AzRestMethod -Path $($workspaceId + "/tables/" + $item.name + "_CL" + "?api-version=2023-01-01-preview") -Method "PUT" -payload $jsonPayload -ErrorAction Stop
        }

        IF ($response.StatusCode -like "2*") {
            Write-Host $(" -> " + $response.StatusCode) -ForegroundColor Green
        }
        ELSE {
            Write-Host $(" -> " + $response.StatusCode) -ForegroundColor Red
            Write-Error $($response.Content)
        }
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

#-------------------------------------------------------------
# 3 - create dedicated DCR per source for EventHubStream to send data into above custom tables
# DCR and DCE needs to be in same region as the workspace
# DCE needs to be created before going with below ARM template
# when using AMPLS, create the DCE in desired region and then associate with AMPLS scope

# NOTE: The stream must named as Custom-MyEventHubStream

$dcrTemplate = @'
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "dataCollectionRuleName": { "type": "string", "defaultValue": "var_dataCollectionRuleName" },
        "workspaceResourceId": { "type": "string", "defaultValue": "var_workspaceId" },
        "endpointResourceId": { "type": "string", "defaultValue": "var_endpointResourceId" },
        "tableName": { "type": "string", "defaultValue": "var_tableName" },
        "consumerGroup": { "type": "string", "defaultValue": "$Default" },
        "location": { "type": "string", "defaultValue": "var_location" }
    },
    "resources": [
        {
            "type": "Microsoft.Insights/dataCollectionRules",
            "name": "[parameters('dataCollectionRuleName')]",
            "location": "[parameters('location')]",
            "apiVersion": "2022-06-01",
            "identity": { "type": "systemAssigned" },
            "properties": {
                "dataCollectionEndpointId": "[parameters('endpointResourceId')]",
                "streamDeclarations": {},
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
                        "streams": [ "Custom-MyEventHubStream" ],
                        "destinations": [ "MyDestinationWorkspace" ],
                        "outputStream": "[concat('Custom-', parameters('tableName'))]"
                    }
                ]
            }
        }
    ]
}
'@

foreach ($table in $dataMap.keys) {
    $item = $datamap[$table]

    # Build streamDeclarations columns
    $columns = $item.columns | ForEach-Object {
        @{
            name = $_.name;
            type = $_.type
        }
    }

    $streamDeclarations = @{
        "Custom-MyEventHubStream" = @{
            columns = $columns
        }
    }

    # Convert base template to object
    $templateObject = $dcrTemplate | ConvertFrom-Json
    $templateObject.resources[0].properties.streamDeclarations = $streamDeclarations

    $dcrName = ("EVH-" + $($item.name + "_" + $resourceSuffix).ToLower())

    $templateObject.parameters.dataCollectionRuleName.defaultValue = $dcrName
    $templateObject.parameters.workspaceResourceId.defaultValue = $workspaceId
    $templateObject.parameters.endpointResourceId.defaultValue = $dce_id
    $templateObject.parameters.tableName.defaultValue = $item.name + "_CL"
    $templateObject.parameters.location.defaultValue = $location

    $TemplateHashTable = $templateObject | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    
    Try {
        Write-Host $("Creating DCR for event hub: " + $item.name) -ForegroundColor Cyan -NoNewline
        $deployment = New-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateObject $TemplateHashTable -DeploymentName $dcrName -ErrorAction Stop

        IF ($deployment.ProvisioningState -ne "Succeeded") {
            Write-Error $("Creating DCR failed due to not expected ProvisioningState: " + $item.name)
        }
        ELSE {
            Write-Host $(" -> " + $deployment.ProvisioningState) -ForegroundColor Green
        }
    }
    Catch {
        Write-Error $("Creating DCR failed for event hub " + $item.name)
        Write-Error $_.Exception.Message
    }
}

#-------------------------------------------------------------
# 4 - assign event hub receiver permission to DCR managed identity (role assignment)

foreach ($table in $dataMap.keys) {
    $item = $datamap[$table]
	
    $dcrName = ("EVH-" + $($item.name + "_" + $resourceSuffix).ToLower())
	$EventHubId = $($eventHubNamespaceId + "/eventhubs/" + $item.name)

	# Get the DCR managed identity
	$dcr = Get-AzResource -ResourceGroupName $resourceGroup -ResourceType "Microsoft.Insights/dataCollectionRules" -ResourceName $dcrName
	$principalId = $dcr.Identity.PrincipalId

	# Assign the Event Hub Data Receiver role to the DCR managed identity
	IF (-not($(Get-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Azure Event Hubs Data Receiver" -Scope $EventHubId))) {
        Write-Host "Assigning Event Hub Data Receiver role to DCR identity for event hub:" $item.name -ForegroundColor Cyan
		New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName "Azure Event Hubs Data Receiver" -Scope $EventHubId
	}
    ELSE {
        Write-Host "Role assignment already exists for event hub:" $item.name -ForegroundColor Green
        continue
    }
}

#-------------------------------------------------------------
# 5 - Associate the data collection rule with the event hub (DCRA)

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

foreach ($table in $dataMap.keys) {
    $item = $datamap[$table]
	
	$dcrName = ("EVH-" + $($item.name + "_" + $resourceSuffix).ToLower())
    $dcrId = $($resourceGroupId + "/providers/Microsoft.Insights/dataCollectionRules/" + $dcrName)
    $dcrAssocName = ("EVH-dcr-assoc-" + $item.name + "_" + $resourceSuffix).ToLower()

	$associateTemplate = $dcrAssociateParams -replace "var_EventHubResourceID", $($eventHubNamespaceId + "/eventhubs/" + $item.name)
    $associateTemplate = $associateTemplate -replace "var_dataCollectionRuleID", $dcrId
    $associateTemplate = $associateTemplate -replace "var_associationName", $dcrAssocName

    $TemplateHashTable = $associateTemplate | ConvertFrom-Json -AsHashtable

    Try {
        $existingAssoc = Invoke-AzRestMethod -Path $($eventHubNamespaceId + "/eventhubs/" + $item.name + "/providers/Microsoft.Insights/dataCollectionRuleAssociations/" + $dcrAssocName + "?api-version=2023-03-11") -Method GET

        IF ( $existingAssoc.StatusCode -like "2*" ) {
            Write-Host $("Associating DCR already done for event hub: " + $item.name) -ForegroundColor Green
            continue
        }
        ELSE {

            Write-Host $("Associating DCR for event hub: " + $item.name) -ForegroundColor Cyan -NoNewline
            $deployment = New-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateObject $TemplateHashTable -DeploymentName $dcrAssocName -ErrorAction Stop
            
            IF ($deployment.ProvisioningState -ne "Succeeded") {
                Write-Error $("Associating DCR failed due to not expected ProvisioningState: " + $item.name)
            }
            ELSE {
                Write-Host $(" -> " + $deployment.ProvisioningState) -ForegroundColor Green
                #$deployment
            }
        }
    }
    Catch {
        Write-Error $("Associating DCR failed for " + $item.name)
        Write-Error $_.Exception.Message
    }    
}
