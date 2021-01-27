# https://github.com/pisinger

<#
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
#>

<#
	Get-AzureEndpoints | select Name -Unique | sort Name
	Get-AzureEndpoints -IPv4 | where Name -like "*frontdoor*" | ft -AutoSize
	Get-AzureEndpoints -IPv4 | where Subnets -like "147.*"
	Get-AzureEndpoints -IPv4 | where Region -like "*ger*" | ft -AutoSize
	Get-AzureEndpoints -IPv4 | where Region -like "*ger*" | where Name -like "sql" | ft
	Get-AzureEndpoints -IPv4 | where Region -like "*ger*"| select Subnets -Unique
	Get-AzureEndpoints -IPv4 | where Name -like *ThreatProtection* | ft
#>

param (
	[string]$Path,
	[switch]$IPv4,
	[switch]$IPv6
)

$LocalCopy = $($PSScriptRoot + "\AzureEndpoints.csv")

# search in PSScriptRoot Folder + Downloads for Source File
IF (!$Path) {
	$Path = (Get-Item $($PSScriptRoot + "\ServiceTags*") | sort LastWriteTime -Descending | select -First 1).Name	
	IF ($Path -eq "" ) {
		$Path = (Get-Item "$env:USERPROFILE\downloads\ServiceTags*.json" | sort LastWriteTime -Descending | select -First 1).FullName
	}
}

# check for recent file
IF(Test-Path $LocalCopy){
	IF ((Get-Item $LocalCopy).LastWriteTime -gt (Get-Date).AddDays(-14)){
		$Endpoints = Import-Csv $LocalCopy
	}
}
ELSEIF ($Path){
	$json = Get-Content $Path | ConvertFrom-Json			
	$results = @()

	$json.values| FOREACH {
		$p = $_
			
		$p.properties.addressPrefixes | FOREACH {				
			$results += [PSCustomObject]@{	
				Name = ($p.Name -split "\.",2)[0]
				SubName = ($p.Name -split "\.",2)[1]
				Region = $p.properties.region
				Service = $p.properties.systemService
				Subnets = $_
			}
		}
	}
	$results | Export-Csv $LocalCopy
	$Endpoints = Import-Csv $LocalCopy
}
ELSE {
	Write-Warning "Either specify file path or check for a newer version. `nDownload from: https://www.microsoft.com/en-us/download/details.aspx?id=56519"
	break
}

IF ($IPv4) {$Endpoints = $Endpoints | where Subnets -notlike "*:*"}
ELSEIF ($IPv6) {$Endpoints = $Endpoints | where Subnets -like "*:*"}
ELSE {}

# output
$Endpoints
