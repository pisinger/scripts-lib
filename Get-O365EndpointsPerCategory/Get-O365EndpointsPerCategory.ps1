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
	.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category Any -Required $True -HttpOnly
	.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category Optimize
	.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category OptimizeAllow -IPsOnly
	.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category OptimizeAllow -URLsOnly
	.\Get-O365EndpointsPerCategory.ps1 -Service Exchange -Category Allow -IPversion IPv6 -Required $True
	.\Get-O365EndpointsPerCategory.ps1 -Service Any -Category Optimize
	.\Get-O365EndpointsPerCategory.ps1 -Category Optimize -IPVersion IPv4
	.\Get-O365EndpointsPerCategory.ps1 -Category OptimizeAllow -URLsOnly
	.\Get-O365EndpointsPerCategory.ps1 -Service Any -Category Allow -Required $True -IPVersion IPv6
	.\Get-O365EndpointsPerCategory.ps1 -Service Common -Category Allow -Required $True -IPversion IPv4
	.\Get-O365EndpointsPerCategory.ps1 -SearchURL uservoice.com
#>

param (
	[ValidateSet("Skype","Exchange","Sharepoint","Common","Any")]
	[string]$Service = "any",
	[ValidateSet("Optimize","OptimizeAllow","Allow","Default","Any")] 
	[array]$Category = "Any",
	[ValidateSet("IPv4","IPv6")]
	[string]$IPVersion,
	[ValidateSet("True","False")]
	[string]$Required,
	[switch]$URLsOnly,
	[switch]$IPsOnly,
	[switch]$HttpOnly,
	[string]$SearchURL
)

# check for recent file
IF(Test-Path "$env:Temp\o365endpoints.json"){
	IF ((Get-Item "$env:Temp\o365endpoints.json").LastWriteTime -gt (Get-Date).AddDays(-1)){
		$Endpoints = Get-Content "$env:Temp\o365endpoints.json" -Encoding utf8 | ConvertFrom-Json
	}
}
ELSE {
	$ClientID = [GUID]::NewGuid().Guid
	$Instance = "Worldwide"
	$EndpointUri = "https://endpoints.office.com/endpoints/" + $Instance + "?clientrequestid=" + $ClientID
	# keep an offline copy
	$Endpoints = Invoke-RestMethod -Uri $EndpointUri -OutFile "$env:temp\o365endpoints.json"
	$Endpoints = Get-Content "$env:Temp\o365endpoints.json" -Encoding utf8 | ConvertFrom-Json
}

#---------------
# pre-filtering
IF ($Service -ne "any") { $Endpoints = $Endpoints | ? {$_.ServiceArea -eq $Service}}

IF ($Category -eq "OptimizeAllow"){ $Endpoints = $Endpoints | ? {$_.Category -eq "Optimize" -or $_.Category -eq "Allow"}; $Category = "Optimize","Allow"}
ELSEIF ($Category -ne "any" -and $Category -ne "OptimizeAllow"){$Endpoints = $Endpoints | ? {$_.Category -eq $Category}}
ELSE { $Category = "Optimize","Allow","Default"}

IF ($Required){ $Endpoints = $Endpoints | ? {$_.required -like $Required}}
IF ($SearchURL) { $Endpoints = $Endpoints | where urls -match "$SearchURL"}
IF ($HttpOnly){ $Endpoints = $Endpoints | ? {$_.tcpports -like "*443*" -or $_.tcpports -like "*80*"}}
IF ($URLsOnly){ $Endpoints = $Endpoints | where urls -ne $NULL | Select -ExpandProperty urls | Sort -Unique}
IF ($IPsOnly) {
	$Endpoints = $Endpoints | ? {$_.ips -ne $NULL} | Select -ExpandProperty ips | Sort -Unique
	IF ($IPversion -eq "IPv4"){$Endpoints = $Endpoints | ? {$_ -like "*.*"}} 
	ELSEIF ($IPVersion -eq "IPv6") {$Endpoints = $Endpoints | ? {$_ -like "*:*"}}
}
#---------------
Write-Output ""

IF ($URLsOnly -or $IPsOnly){$Endpoints}
ELSE {
	$Endpoints | FOREACH {
		IF ($_.Category -in ($Category)){
			Write-Host $_.serviceAreaDisplayName -ForegroundColor Cyan
			Write-Host $_.Category -ForegroundColor Magenta
			
			IF 		($IPVersion -eq "IPv4") { $_.ips | ? {$_ -like "*.*"}}	# only IPv4
			ELSEIF 	($IPVersion -eq "IPv6") { $_.ips | ? {$_ -like "*:*"}}	# only IPv6
			ELSE 	{ $_.ips | ? {$_ -like "*"}}
			
			IF ($_.urls -ne $NULL){$_.urls | Write-Host -ForegroundColor YELLOW}
			IF ($_.tcpports -ne $NULL){$tcp = $_.tcpports + " (tcp)" | out-string; Write-Host $tcp -ForegroundColor GREEN}
			IF ($_.udpports -ne $NULL){$udp = $_.udpports + " (udp)" | out-string; Write-Host $udp -ForegroundColor GREEN}
		}
	}
}
