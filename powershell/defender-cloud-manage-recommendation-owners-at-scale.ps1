# https://pisinger.github.io/posts/defender-cloud-governance-owners-at-scale/

function Invoke-AzResourceGraphQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$query
    )

    $assignments = @()
    $skipToken   = $null

    do {
        $argParams = @{ Query = $query; First = 1000 }
        if ($skipToken) { $argParams["SkipToken"] = $skipToken }

        $page      = Search-AzGraph @argParams
        $assignments += $page.Data ?? $page
        $skipToken  = $page.SkipToken
    } while ($skipToken)

    return $page
}

function Remove-DefenderCloudRecommendationOwnersAtScale {
    param(
        [string]$Method     = "DELETE",
        [string]$apiVersion = "2025-05-04"
    )

    $query = 'securityresources | where type == "microsoft.security/assessments/governanceassignments" | project id'
    $assignments = Invoke-AzResourceGraphQuery -query $query

    $assignments | ForEach-Object {
        try {
            $response = Invoke-AzRest -Method $Method -Path $($_.ResourceId + "?api-version=" + $apiVersion)
            Write-Host $($response.RequestUri) -ForegroundColor Green
        }
        catch {
            Write-Error $_.Exception.Message
        }
    }
}