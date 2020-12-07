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
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory123' -Type EmailAddr
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory123' -Type IpAddrV4 -WriteResultsToFile c:\temp\results.txt
	.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory123' -Type IpAddrV6 -ListAlsoFileNamesWithoutPII
#>

param (
	[Parameter(Mandatory=$True)]
	[string]$Directory,
	[ValidateSet("EmailAddr","IpAddrV4","IpAddrV6","Password")]
	[string]$Type,
	[string]$WriteResultsToFile,
	[switch]$ListAlsoFileNamesWithoutPII
)
	
IF ($WriteResultsToFile){'Matches,FilePath' | Out-File $WriteResultsToFile -Encoding ASCII}
	
# pii filters	
$RegexEmail = "(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b"
$RegexIPv4 = "\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(?<digit>\d)){3}\b"		# false positives for version numbers like AGENT/6.1.1.1
$RegexIPv6 = "(\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*)"
$RegexPassword = "password|pwd|passwort|creds|credential.*"
	
IF ($Type -eq "EmailAddr"){	$RX = $RegexEmail}
ELSEIF($Type -eq "IpAddrV4"){ $RX = $RegexIPv4}	
ELSEIF($Type -eq "IpAddrV6"){ $RX = $RegexIPv6}
ELSEIF($Type -eq "Password"){ $RX = $RegexPassword}
ELSE {Write-Error "Select Switch for Type -> EmailAddr, IpAddrv4, IpAddrV6"; break}
	
$TextFiles = Get-ChildItem $Directory -Include *.txt*,*.csv*,*.rtf*,*.eml*,*.msg*,*.dat*,*.ini*,*.mht*,*.xml*,*.htm*,*.jsp*,*.cfg*,*.conf*,*.php*,*.asp*,*.java*, *.cs*,*.cpp*,*.json*,*.ps1*,*.psm1* -Recurse

# foreach loop adapted from here: 
# https://stackoverflow.com/questions/39983462/use-powershell-to-quickly-search-files-for-regex-and-output-to-csv
foreach ($FileSearched in $TextFiles) {
	
	$matchfound = 0	
	$text = [IO.File]::ReadAllText($FileSearched)			
		
	foreach ($match in ([regex]$RX).Matches($text)) {
		
		IF ($WriteResultsToFile){$match.value,",",$FileSearched.Fullname,"`n" | Out-File $WriteResultsToFile -Encoding ascii -NoNewLine -Append}
		ELSE {$matchfound = 1; break}
	}
	# output for MATCH or NON-MATCH
	IF ($matchfound -eq 1){$FileSearched.Fullname | write-host -foregroundcolor MAGENTA}
	ELSEIF ($ListAlsoFileNamesWithoutPII) {$FileSearched.Fullname | write-host -foregroundcolor GREEN}
	ELSE {}
}
