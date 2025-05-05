# Get-AzureEndpoints

This script downloads "AzureServiceTags" json file and parsing it into csv to get a single subnets per row view. The script always checks for local csv copy and using it for filtering (checking script execution folder). So simply re-run the script to apply filters you are interested in.

Note: First run will take some time due to initial parsing.

> <https://www.microsoft.com/en-us/download/details.aspx?id=56519/>

**Examples:**

```powershell
Get-AzureEndpoints | select Name -Unique | sort Name
Get-AzureEndpoints -IPv4 | where Name -like "*frontdoor*" | ft -AutoSize
Get-AzureEndpoints -IPv4 | where Subnets -like "147.*"
Get-AzureEndpoints -IPv4 | where Region -like "*ger*" | ft -AutoSize
Get-AzureEndpoints -IPv4 | where Region -like "*ger*" | where Name -like "sql" | ft
Get-AzureEndpoints -IPv4 | where Region -like "*ger*"| select Subnets -Unique
Get-AzureEndpoints -IPv4 | where Name -like *ThreatProtection* | ft
Get-AzureEndpoints -IPv4 | group region | sort Count -Descending
Get-AzureEndpoints -IPv4 | where Region -like "*europe*" | group region
Get-AzureEndpoints -IPv4 | where Region -like "*europe*" | group Service | sort Count -Descending
```

**Below examples with output shown:**

```powershell
Get-AzureEndpoints -IPv4 | where Region -like "*ger*" | where Name -like "sql" | ft

Name SubName            Region    Service  Subnets
---- -------            ------    -------  -------
Sql  GermanyNorth       germanyn  AzureSQL 51.116.54.96/27
Sql  GermanyNorth       germanyn  AzureSQL 51.116.54.128/27
Sql  GermanyNorth       germanyn  AzureSQL 51.116.54.192/26
Sql  GermanyNorth       germanyn  AzureSQL 51.116.56.0/27
Sql  GermanyNorth       germanyn  AzureSQL 51.116.57.0/27
Sql  GermanyNorth       germanyn  AzureSQL 51.116.57.32/29
Sql  GermanyWestCentral germanywc AzureSQL 51.116.149.32/27
Sql  GermanyWestCentral germanywc AzureSQL 51.116.149.64/27
Sql  GermanyWestCentral germanywc AzureSQL 51.116.149.128/26
Sql  GermanyWestCentral germanywc AzureSQL 51.116.152.0/27
Sql  GermanyWestCentral germanywc AzureSQL 51.116.152.32/29
Sql  GermanyWestCentral germanywc AzureSQL 51.116.153.0/27
Sql  GermanyWestCentral germanywc AzureSQL 51.116.240.0/27
Sql  GermanyWestCentral germanywc AzureSQL 51.116.240.32/29
Sql  GermanyWestCentral germanywc AzureSQL 51.116.241.0/27
Sql  GermanyWestCentral germanywc AzureSQL 51.116.248.0/27
Sql  GermanyWestCentral germanywc AzureSQL 51.116.248.32/29
Sql  GermanyWestCentral germanywc AzureSQL 51.116.249.0/27
```

```powershell
Get-AzureEndpoints -IPv4 | where Subnets -like "147.*"

Name    : AzureFrontDoor
SubName : Backend
Region  :
Service :
Subnets : 147.243.0.0/16
```

```powershell
Get-AzureEndpoints -IPv4 | where Region -like "*ger*" | ft

Name                        SubName            Region    Service                     Subnets
----                        -------            ------    -------                     -------
ApiManagement               GermanyNorth       germanyn  AzureApiManagement          51.116.0.0/32
ApiManagement               GermanyNorth       germanyn  AzureApiManagement          51.116.59.0/28
ApiManagement               GermanyWestCentral germanywc AzureApiManagement          51.116.96.0/32
ApiManagement               GermanyWestCentral germanywc AzureApiManagement          51.116.155.64/28
AppService                  GermanyNorth       germanyn  AzureAppService             51.116.49.32/27
AppService                  GermanyNorth       germanyn  AzureAppService             51.116.58.160/27
AppService                  GermanyWestCentral germanywc AzureAppService             51.116.145.32/27
AppService                  GermanyWestCentral germanywc AzureAppService             51.116.154.224/27
AppService                  GermanyWestCentral germanywc AzureAppService             51.116.242.160/27
AppService                  GermanyWestCentral germanywc AzureAppService             51.116.250.160/27
AppServiceManagement        GermanyNorth       germanyn  AzureAppServiceManagement   51.116.58.192/26
AppServiceManagement        GermanyWestCentral germanywc AzureAppServiceManagement   51.116.155.0/26
AppServiceManagement        GermanyWestCentral germanywc AzureAppServiceManagement   51.116.156.64/26
AppServiceManagement        GermanyWestCentral germanywc AzureAppServiceManagement   51.116.243.64/26
AppServiceManagement        GermanyWestCentral germanywc AzureAppServiceManagement   51.116.251.192/26
AzureArcInfrastructure      GermanyNorth       germanyn  AzureArcInfrastructure      51.116.49.136/30
AzureArcInfrastructure      GermanyWestCentral germanywc AzureArcInfrastructure      51.116.145.136/30
AzureArcInfrastructure      GermanyWestCentral germanywc AzureArcInfrastructure      51.116.146.212/30
AzureArcInfrastructure      GermanyWestCentral germanywc AzureArcInfrastructure      51.116.158.60/32
AzureBackup                 GermanyNorth       germanyn  AzureBackup                 51.116.55.0/26
```
