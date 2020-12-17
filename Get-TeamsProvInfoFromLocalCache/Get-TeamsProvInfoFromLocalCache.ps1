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

# requires Powershell 6.0 or above

$settings = Get-Content "$env:APPDATA\Microsoft\Teams\settings.json" | ConvertFrom-Json -AsHashtable
$storage = Get-Content "$env:APPDATA\Microsoft\Teams\storage.json" | ConvertFrom-Json -AsHashtable
$storageRaw = Get-Content "$env:APPDATA\Microsoft\Teams\storage.json" 
$desktopconfig = Get-Content "$env:APPDATA\Microsoft\Teams\desktop-config.json" | ConvertFrom-Json -AsHashtable
$skylib = Get-Content "$env:APPDATA\Microsoft\Teams\CS_skylib\CS_shared.conf" | ConvertFrom-Json -AsHashtable
$ipaddr = $storageRaw.Replace('"',"") -match '^*ipaddr:(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})*'
$ipaddr = $matches[1]
$matches = ""

$ProvInfo = [PSCustomObject]@{		
	Ring 			= $settings.ring
	Region 			= $settings.region
	Version			= $settings.version
	Environment		= $settings.environment
	TenantRegion 	= $storage.tenantRegion
	NatIpAddr		= $ipaddr
	UPN 			= $desktopconfig.upnWindowUserUpn
	OrgId			= $desktopconfig.userOid
	TenantId 		= $desktopconfig.userTid
	GuestTenants	= $desktopconfig.tidOidMap
	MediaLogging	= $desktopconfig.appPreferenceSettings.enableMediaLoggingPreferenceKey
	GpuDisabled		= $desktopconfig.appPreferenceSettings.disableGpu
	Language		= $desktopconfig.currentWebLanguage
	WebAccountId	= $desktopconfig.webAccountId
	ElectronVer		= $desktopconfig.lastKnownElectronVersion
	WebClientVer	= $desktopconfig.previousWebClientVersion
	UIVersion		= ($skylib | select '*UIVersion' | fl | Out-String).trim()
}
return $ProvInfo
