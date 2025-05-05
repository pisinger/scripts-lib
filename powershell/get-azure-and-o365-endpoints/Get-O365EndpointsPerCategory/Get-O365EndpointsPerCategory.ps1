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
	.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category OptimizeAllow -IPsOnly -IPVersion IPv4
	.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category OptimizeAllow -URLsOnly
	.\Get-O365EndpointsPerCategory.ps1 -Service Exchange -Category Allow -IPversion IPv6 -Required $True
	.\Get-O365EndpointsPerCategory.ps1 -Service Any -Category Optimize
	.\Get-O365EndpointsPerCategory.ps1 -Category Optimize -IPVersion IPv4
	.\Get-O365EndpointsPerCategory.ps1 -Category OptimizeAllow -URLsOnly
	.\Get-O365EndpointsPerCategory.ps1 -Service Any -Category Allow -Required $True -IPVersion IPv6
	.\Get-O365EndpointsPerCategory.ps1 -Service Common -Category Allow -Required $True -IPversion IPv4
	.\Get-O365EndpointsPerCategory.ps1 -SearchURL office.net | ft

	.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 60 | ft
	.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 180  | where serviceArea -like *skype* | ft
	(.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 180 | where impact -like *remove*).urls | select -Unique
	(.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 180 | where impact -like *add*).urls | select -Unique
	(.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 360 | where impact -like *add*).ips | select -Unique
#>

param (
	[ValidateSet("Skype", "Exchange", "Sharepoint", "Common", "Any")]
	[string]$Service = "any",
	[ValidateSet("Optimize", "OptimizeAllow", "Allow", "Default", "Any")] 
	[array]$Category = "Any",
	[ValidateSet("IPv4", "IPv6")]
	[string]$IPVersion,
	[ValidateSet("True", "False")]
	[string]$Required,
	[switch]$URLsOnly,
	[switch]$IPsOnly,
	[switch]$HttpOnly,
	[string]$SearchURL,
	[int]$ChangesWithinLastNumOfDays
)

$ClientID = [GUID]::NewGuid().Guid
$Instance = "Worldwide"
$FilePath = $($PSScriptRoot + "\o365endpoints.json")
function Get-O365Endpoints {
	# check for recent file	
	IF (Test-Path $FilePath) {
		IF ((Get-Item $FilePath).LastWriteTime -gt (Get-Date).AddDays(-1)) {
			$Endpoints = Get-Content $FilePath -Encoding utf8 | ConvertFrom-Json
		}
	}
	ELSE {
		$EndpointUri = "https://endpoints.office.com/endpoints/" + $Instance + "?clientrequestid=" + $ClientID
		# keep an offline copy
		Invoke-RestMethod -Uri $EndpointUri -OutFile $FilePath
		$Endpoints = Get-Content $FilePath -Encoding utf8 | ConvertFrom-Json
	}
	return $Endpoints
}

IF ($ChangesWithinLastNumOfDays) {
	# download or load local M365 Endpoints file
	$Endpoints = Get-O365Endpoints

	# define time delta
	# Version = <YYYYMMDDNN>
	## $latestVersions = Invoke-RestMethod $("https://endpoints.office.com/version" + "?clientrequestid=" + $ClientID)
	$DateChanges = (Get-Date).AddDays(-$ChangesWithinLastNumOfDays); $DateChanges = "{0:yyyyMMdd00}" -f $DateChanges
	$FilePath = $($PSScriptRoot + "\o365endpoints_" + $DateChanges + ".json")

	# check for recent file
	IF (Test-Path $FilePath) {
		$EndpointsChanged = Get-Content $FilePath -Encoding utf8 | ConvertFrom-Json
	}
	ELSE {
		$EndpointUriChanges = "https://endpoints.office.com/changes/" + $Instance + "/" + $DateChanges + "?clientrequestid=" + $ClientID
		$EndpointsChanged = Invoke-RestMethod $EndpointUriChanges -OutFile $FilePath
		$EndpointsChanged = Get-Content $FilePath -Encoding utf8 | ConvertFrom-Json
	}

	$results += foreach ($endp in $EndpointsChanged) {

		IF ($rm = $endp | Select-Object -ExpandProperty remove -ErrorAction SilentlyContinue) {}
		#IF ($add = $endp | Select-Object -ExpandProperty remove -ErrorAction SilentlyContinue) {}

		# map endpointSetId with service id
		$serviceArea = $Endpoints | Where-Object id -eq $endp.endpointSetId
		[PSCustomObject]@{
			serviceArea = $serviceArea.serviceArea
			endpointId	= $endp.endpointSetId
			version 	= $endp.version
			category    = $serviceArea.category
			required    = $serviceArea.required
			protocol	= IF ($serviceArea.tcpPorts) { "tcp" } ELSEIF ($serviceArea.udpPorts) { "udp" } ELSE {}
			ports       = IF ($tcp = $serviceArea.tcpports) { $tcp } ELSE { $serviceArea.udpPorts }
			impact      = $endp.impact
			ips         = IF ($rm) { ($endp | Select-Object -ExpandProperty remove -ErrorAction SilentlyContinue).ips } ELSE { ($endp | Select-Object -ExpandProperty add -ErrorAction SilentlyContinue).ips }
			urls        = IF ($rm) { ($endp | Select-Object -ExpandProperty remove -ErrorAction SilentlyContinue).urls } ELSE { ($endp | Select-Object -ExpandProperty add -ErrorAction SilentlyContinue).urls }
			notesPre    = $endp.previous.notes
			notesCur    = $endp.current.notes
		}
	}
	$results = $results |Sort-Object version -Descending
	return $results
}
ELSE {
	# download or load local M365 Endpoints file
	$Endpoints = Get-O365Endpoints
	
	$results += foreach ($endp in $Endpoints) {
		[PSCustomObject]@{
			id 			= $endp.id
			serviceArea = $endp.serviceArea
			category    = $endp.category
			required    = $endp.required
			protocol	= IF ($endp.tcpPorts) { "tcp" } ELSEIF ($endp.udpPorts) { "udp" } ELSE {}
			ports       = IF ($tcp = $endp.tcpPorts) { $tcp } ELSE { $endp.udpPorts}
			ipsv4       = ($endp).ips | Where-Object { $_ -like "*.*" }
			ipsv6     	= ($endp).ips | Where-Object { $_ -like "*:*" }
			urls        = ($endp).urls
			notes      	= $endp.notes
		}
	}
	
	#---------------
	# pre-filtering
	IF ($Service -ne "any") { $results = $results | Where-Object { $_.ServiceArea -eq $Service } }
	
	IF ($Category -eq "OptimizeAllow") { $results = $results | Where-Object { $_.Category -eq "Optimize" -or $_.Category -eq "Allow" }; $Category = "Optimize", "Allow" }
	ELSEIF ($Category -ne "any" -and $Category -ne "OptimizeAllow") { $results = $results | Where-Object { $_.Category -eq $Category } }
	ELSE { $Category = "Optimize", "Allow", "Default" }

	IF ($Required) 	{ $results = $results | Where-Object required -like $Required }
	IF ($SearchURL) { $results = $results | Where-Object urls -match "$SearchURL" }
	IF ($HttpOnly) 	{ $results = $results | Where-Object { $_.ports -like "*443*" -or $_.ports -like "*80*" -and $_.protocol -ne "udp" }}
	IF ($URLsOnly) 	{ $results = $results | Where-Object urls -ne $NULL | Select-Object -ExpandProperty urls | Sort-Object -Unique }
	IF ($IPversion -eq "IPv4") 	{ $results = $results | where-object ipsv4 -ne $NULL | select-object -ExcludeProperty ipsv6 }
	IF ($IPversion -eq "IPv6") 	{ $results = $results | where-object ipsv6 -ne $NULL | select-object -ExcludeProperty ipsv4 }

	IF ($IPsOnly) {
		$results = $results | Where-Object { $_.ipsv4 -ne $NULL -or $_.ipsv6 -ne $NULL } | Sort-Object ipsv4, ipsv6 -Unique | Select-Object ipsv4, ipsv6
		IF ($IPversion -eq "IPv4") 		{ $results = $results.ipsv4 | Sort-Object -Unique }
		ELSEIF ($IPVersion -eq "IPv6") 	{ $results = $results.ipsv6 | Sort-Object -Unique }
	}
	#---------------
	return $results
}