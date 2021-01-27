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
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type EmailAddr
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type IpAddrV4 -WriteResultsToFile c:\temp\results.txt
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type IpAddrV6 -ShowAlsoFileNamesWithoutPII
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type StringToSearch -SearchString john.doe -ShowMatches
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type StringToSearch -SearchString "1234-0000-1234" -ShowMatches
#>

param (
	[Parameter(Mandatory=$True)]
	[string]$Directory,
	[ValidateSet("EmailAddr","IpAddrV4","IpAddrV6","Password","StringToSearch")]
	[string]$Type,
	[string]$SearchString,
	[string]$WriteResultsToFile,
	[switch]$ShowAlsoFileNamesWithoutPII,
	[switch]$ShowMatches
)
	
IF ($WriteResultsToFile){'Matches,FilePath' | Out-File $WriteResultsToFile -Encoding ASCII}
IF ($Type -eq "StringToSearch" -and !($SearchString)){ $SearchString = Read-Host "ENTER STRING"}
	
# pii filters	
$RegexEmail = "(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b"
$RegexIPv4 = "\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"	# false positives for version numbers like AGENT/6.1.1.1
$RegexIPv6 = "(\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*)"
$RegexPassword = "password|pwd|passwort|creds|credential.*"
$RegexStringToSearch = "($SearchString).+?(?=\s)"
	
IF ($Type -eq "EmailAddr"){	$RX = $RegexEmail}
IF ($Type -eq "IpAddrV4"){ $RX = $RegexIPv4}	
IF ($Type -eq "IpAddrV6"){ $RX = $RegexIPv6}
IF ($Type -eq "Password"){ $RX = $RegexPassword}
IF ($Type -eq "StringToSearch"){ $RX = $RegexStringToSearch}
	
$TextFiles = Get-ChildItem $Directory -Include *.txt,*.csv,*.rtf*,*.eml*,*.dat,*.ini,*.mht*,*.xml*,*.htm*,*.jsp*,*.cfg*,*.conf,*.config,*.php*,*.asp*,*.java*, *.cs*,*.cpp*,*.json*,*.ps1*,*.psm1* -Exclude *lnk -Recurse

# foreach loop adapted from here: 
# https://stackoverflow.com/questions/39983462/use-powershell-to-quickly-search-files-for-regex-and-output-to-csv
foreach ($FileSearched in $TextFiles) {
	
	$matchfound = 0	
	$text = [IO.File]::ReadAllText($FileSearched)
	
	# ignore case sensitive
	$RX = [regex]::new($RX,([regex]$RX).Options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)	
	
	foreach ($match in ([regex]$RX).Matches($text)) {		
		# match found - break after first match and go to next file
		$matchfound = 1	
		break;
	}
	
	# output for MATCH or NON-MATCH	
	IF ($matchfound -eq 1 -and $WriteResultsToFile){
		$x = $FileSearched.Fullname + "," + $match.value
		$x = ($x | out-string).trim()
		$x | Out-File $WriteResultsToFile -Encoding ascii -Append
	}		
	ELSEIF ($matchfound -eq 1 -and $ShowMatches) {
		$FileSearched.Fullname | write-host -foregroundcolor MAGENTA -NoNewLine
		"`t" | write-host -NoNewLine
		$match.value | write-host -foregroundcolor YELLOW
	}
	ELSEIF ($matchfound -eq 1) {
		$FileSearched.Fullname | write-host -foregroundcolor MAGENTA
	}
	ELSEIF ($ShowAlsoFileNamesWithoutPII) {
		$FileSearched.Fullname | write-host -foregroundcolor GREEN
	}
	ELSE {
	}
}
