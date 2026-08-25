function Get-DefenderCloudExportSettings {
    param(
        [Parameter(Mandatory)]
        [guid]$subId,
        
        [Parameter(Mandatory)]
        [string]$resourceGroup,

        [string]$automationName
    )

    $baseUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$resourceGroup/providers/Microsoft.Security/automations"
    $uri = if ($automationName) {
        $($baseUri + "/" + $automationName + "?api-version=2023-12-01-preview")
    } else {
        $($baseUri + "?api-version=2023-12-01-preview")
    }

    $result = (Invoke-AzRestMethod -Uri $uri -Method GET).Content | ConvertFrom-Json
    if ($automationName) { $result } else { $result.value }
}