function Export-SentinelAnalyticRules {
	
	param(
		[Parameter(Mandatory = $true)]
		[string]$SubscriptionId,
		
		[Parameter(Mandatory = $true)]
		[string]$ResourceGroup,
		
		[Parameter(Mandatory = $true)]
		[string]$WorkspaceName,
		
		[switch]$ExportQueryOnly
	)
	
	# Variables
	$OutputFolder   = ".\SentinelRulesExport"
	$OutputFolderFull = $($OutputFolder + "\full")
	$OutputFolderSimple = $($OutputFolder + "\simple")

	# Create output folder
	if (-not(Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
	if (-not(Test-Path $OutputFolderFull)) { New-Item -ItemType Directory -Path $OutputFolderFull | Out-Null }
	if (-not(Test-Path $OutputFolderSimple)) { New-Item -ItemType Directory -Path $OutputFolderSimple | Out-Null }

	if (-not(Test-Path $(join-Path $OutputFolderFull "disabled"))) { New-Item -ItemType Directory -Path $(join-Path $OutputFolderFull "disabled") | Out-Null }
	if (-not(Test-Path $(join-Path $OutputFolderSimple "disabled"))) { New-Item -ItemType Directory -Path $(join-Path $OutputFolderSimple "disabled") | Out-Null }

	# Get all analytic rules (Scheduled + NRT)
	$Rules = Invoke-AzRestMethod -Method GET -Path `
	"/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-11-01-preview"

	$RulesJson = ($Rules.Content | ConvertFrom-Json).value

	# Filter Scheduled + NRT
	$Filtered = $RulesJson | Where-Object { $_.kind -eq "Scheduled" -or $_.kind -eq "NRT" }

	IF($ExportQueryOnly) { $OutputFolder = $OutputFolderSimple }
	ELSE { $OutputFolder = $OutputFolderFull }

	# Export each rule to JSON
	foreach ($r in $Filtered) {
		$fileName = $r.properties.displayName
		$fileName = ((($($fileName + ".json") -replace "\[","(" ) -replace "\]",")" ) -replace '\/',' ') -replace ":"," -"
		
		IF ($r.properties.enabled -eq "True") {
			Write-Host $($FileName + " -> ") -ForegroundColor GREEN -NoNewLine
			Write-Host $r.properties.enabled -ForegroundColor CYAN
			$DestFolder = $OutputFolder 
		}
		ELSE {
			Write-Host $($FileName + " -> ") -ForegroundColor YELLOW -NoNewLine
			Write-Host $r.properties.enabled -ForegroundColor YELLOW
			$DestFolder = Join-Path $OutputFolder "disabled"
		}
		   
		IF ($ExportQueryOnly) {
			$filePath = (Join-Path $DestFolder $fileName) -replace "json","kql"
			$r.properties.query | Out-File $filePath -Encoding utf8
		}
		ELSE {
			$filePath = Join-Path $DestFolder $fileName
			$r | ConvertTo-Json -Depth 50 | Out-File $filePath -Encoding utf8
		}
	}
}