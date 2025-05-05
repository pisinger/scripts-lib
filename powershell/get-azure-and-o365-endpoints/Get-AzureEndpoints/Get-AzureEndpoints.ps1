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
	Get-AzureEndpoints -IPv4 | group region | sort Count -Descending
	Get-AzureEndpoints -IPv4 | where Region -like "*europe*" | group region
	Get-AzureEndpoints -IPv4 | where Region -like "*europe*" | group Service | sort Count -Descending
#>

param (
	[switch]$IPv4,
	[switch]$IPv6
)

$LocalCopy = $($PSScriptRoot + "\AzureEndpoints.csv")

# check for recent file
IF(Test-Path $LocalCopy){
	IF ((Get-Item $LocalCopy).LastWriteTime -gt (Get-Date).AddDays(-7)){
		$Endpoints = Import-Csv $LocalCopy
	}
}
ELSE {
	# download endpoint file
	$href = Invoke-WebRequest -Method Get -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
	$downloadUri = ($href.links | Where-Object href -like "*download.microsoft.com*.json" | Select-Object -first 1).href
	$fileName = $downloadUri | Split-Path -Leaf
	Invoke-WebRequest -Method Get -Uri $downloadUri -Outfile $($PSScriptRoot + "\" + $fileName)
	
	$json = Get-Content $($PSScriptRoot + "\" + $fileName) | ConvertFrom-Json
	
	$results += $json.values| ForEach-Object {
		$p = $_
			
		$p.properties.addressPrefixes | ForEach-Object {
			[PSCustomObject]@{
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

IF ($IPv4) {$Endpoints = $Endpoints | Where-Object Subnets -notlike "*:*"}
ELSEIF ($IPv6) {$Endpoints = $Endpoints | Where-Object Subnets -like "*:*"}
ELSE {}

# output
$Endpoints
