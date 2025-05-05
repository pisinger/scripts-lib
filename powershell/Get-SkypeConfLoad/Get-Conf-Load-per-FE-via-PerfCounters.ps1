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
	GlobalHealthState:
	1 – normal
	2 – light load
	3 – heavy load
	4 - overload
	
	McuHealthStates
	0 - Normal
	1 - Loaded
	2 - Full (max reached)
	3 - Unavailable
#>

$computers = (Get-CsPool | ? {$_.Services -like "*UserServer*"}).Computers

$output = Invoke-Command -ComputerName $Computers -ScriptBlock {

	$Counters = @(
		"\Processor Information(_total)\% Processor Utility",				#0
		"\Memory\Available MBytes",											#1					
		"\LS:USrv - Endpoint Cache\USrv - Active Registered Users",			#2
		"\LS:SIP - Peers(_total)\SIP - Connections Active",					#3
		"\LS:ImMcu - IMMcu Conferences\IMMCU - Active Conferences",			#4
		"\LS:ImMcu - IMMcu Conferences\IMMCU - Connected Users",			#5
		"\LS:AVMCU - Operations\AVMCU - Number of Conferences",				#6
		"\LS:AVMCU - Operations\AVMCU - Number of Users",					#7
		"\LS:AsMcu - AsMcu Conferences\ASMCU - Active Conferences",			#8
		"\LS:AsMcu - AsMcu Conferences\ASMCU - Connected Users",			#9
		"\LS:AsMcuUpdate - AsMcu Conferences\AsMcuUpdate - Active Vbss Conferences",	#10
		#"\LS:AsMcu - AsMcu Conferences\ASMCU - Active Vbss Conferences",				#10 - Skype 2019
		"\LS:AsMcuUpdate - AsMcu Conferences\AsMcuUpdate - Active Vbss Users",			#11
		#"\LS:AsMcu - AsMcu Conferences\ASMCU - Active Vbss Users",						#11 - Skype 2019
		"\LS:ImMcu - MCU Health And Performance\IMMCU - MCU Health State",			#12
		"\LS:DATAMCU - MCU Health And Performance\DATAMCU - MCU Health State",		#13
		"\LS:AvMcu - MCU Health And Performance\AVMCU - MCU Health State",			#14
		"\LS:AsMcu - MCU Health And Performance\ASMCU - MCU Health State",			#15
		"\LS:MEDIA - Operations(AVMCUsvc.exe)\MEDIA - Global health",				#16
		"\LS:MEDIA - Operations(ASMCUsvc.exe)\MEDIA - Global health",				#17					
		"\LS:MEDIA - Planning(_total)\MEDIA - Number of conferences with NORMAL health",		#18
		"\LS:MEDIA - Planning(_total)\MEDIA - Number of conferences with OVERLOADED health",	#19					
		"\LS:MediationServer - Outbound Calls(_total)\- Current",			#20
		"\LS:MediationServer - Inbound Calls(_total)\- Current",			#21
		"\LS:MEDIA - Operations(MediationServer)\MEDIA - Global health"		#22
	)
	
	$results = get-counter -counter $counters | select -expand countersamples | select cookedvalue
	
	$object = [PSCustomObject]@{
		Date        = "{0:dd.MM.yyyy HH:mm}" -f (Get-date)
		Computer    = hostname						
		'CPU%' 		= [math]::Round($results[0].CookedValue)
		RamFree		= $results[1].CookedValue					
		ActiveUsers			= $results[2].CookedValue
		SipConnections		= $results[3].CookedValue
		ImMcuConfs			= $results[4].CookedValue
		ImMcuUsers 			= $results[5].CookedValue
		AvMcuConfs			= $results[6].CookedValue
		AVMcuUsers 			= $results[7].CookedValue
		AsMcuConfs			= $results[8].CookedValue
		AsMcuUsers 			= $results[9].CookedValue
		VbssMcuConfs 		= $results[10].CookedValue
		VbssMcuUsers 		= $results[11].CookedValue
		ImMcuHealthState 	= $results[12].CookedValue
		DataMcuHealthState 	= $results[13].CookedValue
		AvMcuHealthState 	= $results[14].CookedValue
		AsMcuHealthState 	= $results[15].CookedValue					
		AvMcuHealthGlobal	= $results[16].CookedValue
		AsMcuHealthGlobal 	= $results[17].CookedValue					
		McusNormalState		= $results[18].CookedValue
		McusOverloaded 		= $results[19].CookedValue
		MediationCallsOut	= $results[20].CookedValue
		MediationCallsIn	= $results[21].CookedValue
		MediationHealth		= $results[22].CookedValue
	}
	return $object
}

$output = $output | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSSourceJobInstanceId
$output | fl

<#
	$ExportPath = "C:\temp\mcu-load.csv"
	IF (Get-item $ExportPath -ErrorAction SilentlyContinue) {
		$output | Export-Csv $ExportPath -Append
	}
	ELSE {
		$output | Export-Csv $ExportPath
	}
#>