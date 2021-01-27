# scripts-lib
 
This repo is used for smaller scripts and functions

**Create-PerfCountersViaWinRM:**
Creating Windows Perf Counters for multiple computers remotely

**Get-TeamsProvInfoFromLocalCache:**
Get some Teams Client provisioning Info from local AppData cache

**Find-PII-Data-in-Files:**
This script does search for PII data in files.

**Get-O365EndpointsPerCategory:**
This script connects to O365 endpoints RestAPI and keeping an offline version to run the script more efficient and to avoid making same requests to query for same data much often.

**Get-AzureEndpoints:**
This script loads previously downloaded "AzureServiceTags" json file and parsing it into csv to get a single subnets per row view. The script always checks for local csv copy and using it for filtering (checking downloads and script execution folder). So simply re-run the script to apply filters you are interested in.
