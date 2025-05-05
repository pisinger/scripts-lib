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

param (
	[array]$Computers,	# "Node01","Node02","Node03"
	[switch]$SkypeFrontEnds
)

IF ($SkypeFrontEnds) {$computers = (Get-CsPool | ? {$_.Services -like "*UserServer*"}).Computers; $EventService = "Lync Server"}
ELSEIF ($Computers) {$computers = $computers; $EventService = "Windows Powershell"}
ELSE {$computers = "localhost"; $EventService = "Windows Powershell"}

Invoke-Command -ComputerName $Computers -ScriptBlock {
	$Counters = @(
		"\Memory\Available MBytes"
		"\LS:USrv - Endpoint Cache\USrv - Active Registered Users",
		"\LS:AVMCU - Operations\AVMCU - Number of Users",
		"\LS:AsMcu - AsMcu Conferences\ASMCU - Connected Users"
	)
	
	$results = get-counter -counter $counters -ErrorAction SilentlyContinue | select-object -expand countersamples | select-object cookedvalue
	
	# cpu
	$resultsCPU = get-counter -counter "\Processor(*)\% Processor Time" -ErrorAction SilentlyContinue | select-object -expand countersamples | select-object cookedvalue              
	$cputimes = @(); $resultsCPU | foreach {$cputimes += [math]::round($_.cookedvalue)}
	
	$cpu = Get-CimInstance Win32_processor | select-object Name, NumberOfLogicalProcessors, MaxClockSpeed
	$cores = 0
	$cpu | foreach {$cores += $_.NumberOfLogicalProcessors}
	
	# network
	$resultsPacketsDiscarded = (Get-Counter "\Network Interface(*)\Packets Received Discarded") | select-object -expand countersamples | where-object InstanceName -notlike "*isatap*" | select-object cookedvalue
	$NetPacketsDiscarded = @(); $resultsPacketsDiscarded | foreach {$NetPacketsDiscarded += [math]::round($_.cookedvalue)}
	
	$resultsPacketsSent = (Get-Counter "\Network Interface(*)\Bytes Sent/sec") | select-object -expand countersamples | where-object InstanceName -notlike "*isatap*" | select-object cookedvalue
	$NetPacketsSent = @(); $resultsPacketsSent | foreach {$NetPacketsSent += ([math]::round(($_.cookedvalue )*8 /1gb,3)).ToString("0.000")}
	
	$resultsPacketsRecv = (Get-Counter "\Network Interface(*)\Bytes Received/sec") | select-object -expand countersamples | where-object InstanceName -notlike "*isatap*" | select-object cookedvalue
	$NetPacketsRecv = @(); $resultsPacketsRecv | foreach {$NetPacketsRecv += ([math]::round(($_.cookedvalue )*8 /1gb,3)).ToString("0.000")}
	
	# processes
	$ProcHighCpuTime = (Get-Counter "\Process(*)\% Processor Time" -ErrorAction SilentlyContinue).CounterSamples | where-object InstanceName -notmatch '_total|memory compression|idle|system' | select-object InstanceName, CookedValue | sort-object CookedValue -Descending | select-object -First 1
	$ProcHighRead = (Get-Counter "\Process(*)\IO Read Bytes/sec" -ErrorAction SilentlyContinue).CounterSamples | where-object InstanceName -notmatch '_total|memory compression|idle|system' | select-object InstanceName, CookedValue | sort-object CookedValue -Descending | select-object -First 1
	$ProcHighWrite = (Get-Counter "\Process(*)\IO Write Bytes/sec" -ErrorAction SilentlyContinue).CounterSamples | where-object InstanceName -notmatch '_total|memory compression|idle|system' | select-object InstanceName, CookedValue | sort-object CookedValue -Descending | select-object -First 1
	$ProcMostThreads = (Get-Counter "\Process(*)\Thread Count" -ErrorAction SilentlyContinue).CounterSamples | where-object InstanceName -notmatch '_total|memory compression|idle|system' | select-object InstanceName, CookedValue | sort-object CookedValue -Descending | select-object -First 1
	
	# os
	$os = Get-CimInstance Win32_OperatingSystem
	$LastUpdate = (Get-WinEvent -FilterHashTable @{LogName="SETUP";ProviderName="Microsoft-Windows-Servicing";ID=2} | ? {$_.Message -like "*KB*"} | select-object -First 1).TimeCreated
	
	# events
	$today = (Get-Date -Hour 0 -Minute 00 -Second 00)
	$LastHour = (Get-Date).AddHours(-1)         
	$events = Get-WinEvent -FilterHashtable @{LogName = "System","Application","setup"; StartTime = $today; Level = 1,2,3}
	$eventsLastHour = $events | where-object TimeCreated -gt $LastHour             
	$EventTopProvider = (($events | group-object ProviderName | sort-object Count -Descending) | select-object -First 1)
	$EventTopId = ($events | group-object Id | sort-object Count -Descending | select-object -First 1).Name         
	
	$eventsService = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{LogName = $using:eventService; StartTime = $today; Level = 1,2,3}
	$EventTopService = ($eventsService | group-object ProviderName | sort-object Count -Descending | select-object -First 1)
	$EventTopServiceId = ($eventsService | group-object Id | sort-object Count -Descending | select-object -First 1).Name
	$eventsServiceLastHour = $eventsService | where-object TimeCreated -gt $LastHour
	
	# disk
	$partitions = Get-PSDrive -Name C,D,E -ErrorAction SilentlyContinue
	
	# memory
	$memory = (Get-CimInstance win32_operatingsystem) | select-object TotalVirtualMemorySize, TotalVisibleMemorySize
	$MemoryFree = [math]::Round(($results[0].CookedValue)/1kb,3)
	
	$Processes = Get-Process | Group-Object -Property ProcessName	
	$procHighMem = foreach ($Process in $Processes) {[PSCustomObject]@{ProcessName = $Process.Name;Memory = ($Process.Group | Measure-Object WorkingSet -Sum).Sum}}
	
	$object = [PSCustomObject]@{
		Date        = Get-date
		Computer    = $env:COMPUTERNAME                 
		SysBootTime    	= $os.LastBootUpTime
		SysOS          	= $os.Caption
		SysBuild		= ([System.Environment]::OSVersion).Version
		SysLastUpdate	= $LastUpdate 
		SysModel       	= $((Get-CimInstance Win32_ComputerSystem).Model)
		CpuName    		= $cpu.Name | select-object -first 1
		CpuMaxClock 	= $cpu.MaxClockSpeed
		CpuCores   		= $cpu.NumberOfLogicalProcessors            
		'CpuTotal%'     = $cputimes[-1]
		'CpuPerCore%'   = $cputimes[0..$($cputimes.Length - 2)]
		MemoryGB		= [math]::Round(($memory.TotalVisibleMemorySize)/1mb)
		MemoryFreeGB    = $MemoryFree					
		MemoryPagedGB   = [math]::Round(($memory.TotalVirtualMemorySize - $memory.TotalVisibleMemorySize)/1mb,3)
		'MemoryUsed%'   = [math]::Round((($memory.TotalVisibleMemorySize) - $MemoryFree*1mb) / $memory.TotalVisibleMemorySize * 100)                
		ServicesRunning     = (Get-Service | where-object Status -eq "running").count
		ProcessesRunning    = (Get-Process).count
		ProcHighCpuTime     = $ProcHighCpuTime.InstanceName
		'ProcHighCpuTime%'  = [math]::Round(($ProcHighCpuTime.CookedValue)/$cores,2)
		ProcHighMem         = ($ProcHighMem | sort-object -Descending Memory | select-object -First 1).ProcessName
		ProcHighMemGB       = [math]::Round(($ProcHighMem | sort-object -Descending Memory | select-object -First 1).Memory/1gb,3)                    
		ProcHighRead        = $ProcHighRead.InstanceName
		ProcHighReadMB      = [math]::Round($ProcHighRead.CookedValue/1mb,3)
		ProcHighWrite       = $ProcHighWrite.InstanceName
		ProcHighWriteMB     = [math]::Round($ProcHighWrite.CookedValue/1mb,3)                   
		ProcMostThreads     = $ProcMostThreads.InstanceName
		ProcMostThreadsCount = $ProcMostThreads.CookedValue
		DiskFreeC   = [math]::Round($partitions[0].Free/1gb)
		DiskFreeD   = [math]::Round($partitions[1].Free/1gb)
		DiskFreeE   = [math]::Round($partitions[2].Free/1gb)
		NetPacketsDiscarded = $NetPacketsDiscarded
		NetPacketsSentGbps  = $NetPacketsSent
		NetPacketsRecvGbps  = $NetPacketsRecv
		EventsLastHour      = $eventsLastHour.count
		EventsCrit          = ($events | where-object Level -eq 1).Count
		EventsError         = ($events | where-object Level -eq 2).Count                    
		EventsWarn          = ($events | where-object Level -eq 3).Count                   
		EventTopProvider    = $EventTopProvider.Name
		EventTopId          = $EventTopId
		EventTopCount       = $EventTopProvider.Count
		EventsServiceCrit   = ($eventsService | where-object Level -eq 1).Count
		EventsServiceError  = ($eventsService | where-object Level -eq 2).Count              
		EventsServiceWarn   = ($eventsService | where-object Level -eq 3).Count
		EventTopService       = $EventTopService.Name
		EventTopServiceId     = $EventTopServiceId
		EventTopServiceCount  = $EventTopService.Count
		EventsServiceLastHourCrit   = ($eventsServiceLastHour | where-object Level -eq 1).Count
		EventsServiceLastHourError	= ($eventsServiceLastHour | where-object Level -eq 2).Count
		EventsServiceLastHourWarn   = ($eventsServiceLastHour | where-object Level -eq 3).Count                   
		SkypeUsersActive    = $results[1].CookedValue   
		SkypeUsersAvMcu     = $results[2].CookedValue
		SkypeUsersAsMcu     = $results[3].CookedValue
	}
	return $object
}
