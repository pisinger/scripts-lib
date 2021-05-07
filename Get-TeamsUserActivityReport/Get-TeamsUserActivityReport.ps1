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
	NOTE: 
	The snipplet does cover downloading and parsing of the TeamsUserActivityUserDetail report only.
	Not included is the step to acquire an access token to call the report api
#>

# Teams - User Activity Reports
#  D7, D30, D90, and D180
$apiUrl = "https://graph.microsoft.com/beta/reports/getTeamsUserActivityUserDetail(period='D30')"
$Data = Invoke-RestMethod -Headers @{Authorization = "Bearer $ACCESSTOKEN"} -Uri $apiUrl -Method Get
$data = $data -split '\n' | Select-Object -skip 1

function ConvertFrom-ISO8601Duration {
# https://github.com/martin77s/PS/blob/master/Scripts/ConvertFrom-ISO8601Duration.ps1

    [CmdletBinding(SupportsShouldProcess = $false)]
    [OutputType([System.TimeSpan])]

    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Alias('ISO8601', 'String')]
        [string]$Duration
    )

    [System.Xml.XmlConvert]::ToTimeSpan($Duration.ToUpper())
}

$list = [System.Collections.Generic.List[Object]]::new()
# skiplast as NULL line
$data | Select-Object -skipLast 1 | ForEach-Object {
    $col = $_ -split ","
	
	$audioDuration = ConvertFrom-ISO8601Duration -ISO8601 $col[18]
	$audioDurationHours = ([Math]::Floor($audioDuration.TotalHours))
	$audioDurationMinutes = ([timespan]::FromHours($audioDuration.TotalHours - $audioDurationHours))
	$AudioDuration = $($audioDurationHours.ToString() + (($audioDurationMinutes.toString()).TrimStart("0"))) 
	
	$videoDuration = ConvertFrom-ISO8601Duration -ISO8601 $col[19]
	$videoDurationHours = ([Math]::Floor($videoDuration.TotalHours))
	$videoDurationMinutes = ([timespan]::FromHours($videoDuration.TotalHours - $videoDurationHours))
	$VideoDuration = $($videoDurationHours.ToString() + (($videoDurationMinutes.toString()).TrimStart("0"))) 
	
	$screenShareDuration = ConvertFrom-ISO8601Duration -ISO8601 $col[20]
	$screenShareDurationHours = ([Math]::Floor($screenShareDuration.TotalHours))
	$screenShareDurationMinutes = ([timespan]::FromHours($screenShareDuration.TotalHours - $screenShareDurationHours)) 
	$screenShareDuration = $($screenShareDurationHours.ToString() + (($screenShareDurationMinutes.toString()).TrimStart("0"))) 
	
	$list.Add($(
			[pscustomobject]@{
				'Report Refresh Date' = $col[0]
				'User Principal Name' = $col[1]
				'Last Activity Date' = $col[2]
				'Is Deleted' = $col[3]
				'Deleted Date' = $col[4]
				'Assigned Products' = $col[5]
				'Team Chat Message Count' = $col[6]
				'Private Chat Message Count' = $col[7]
				'Call Count' = $col[8]
				'Meeting Count' = $col[9]
				'Meetings Organized Count' = $col[10]
				'Meetings Attended Count' = $col[11]
				'Ad Hoc Meetings Organized Count' = $col[12]
				'Ad Hoc Meetings Attended Count' = $col[13]
				'Scheduled One-time Meetings Organized Count' = $col[14]
				'Scheduled One-time Meetings Attended Count' = $col[15]
				'Scheduled Recurring Meetings Organized Count' = $col[16]
				'Scheduled Recurring Meetings Attended Count' = $col[17]
				'Audio Duration' = $AudioDuration 
				'Video Duration' = $VideoDuration 
				'Screen Share Duration' = $screenShareDuration
				'Audio Duration In Seconds' = $col[21]
				'Video Duration In Seconds' = $col[22]
				'Screen Share Duration In Seconds' = $col[23]
				'Has Other Action' = $col[24]
				'Is Licensed' = $col[25]
				#'Report Period' = $col[26]
			}
		)
	)
}

$list | Export-Csv "TeamsUserActivityUserDetail.csv"
