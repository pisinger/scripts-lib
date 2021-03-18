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

$computers = (Get-CsPool | ? {$_.Services -like "*UserServer*"}).Computers
#$computers = "Node01","Node02","Node03"

workflow FLOW {
    param ([string[]]$computers)
    
    FOREACH -parallel ($computer in $computers){    
        InlineScript {
            
            Invoke-Command -ComputerName $using:Computer -ScriptBlock {
                $Counters = @(
                    "\Processor Information(_total)\% Processor Utility",
                    "\Processor Information(0,0)\% Processor Utility",
                    "\Processor Information(0,1)\% Processor Utility",
                    "\Processor Information(0,2)\% Processor Utility",
                    "\Processor Information(0,3)\% Processor Utility", 
                    "\Memory\Available MBytes"
                    "\LS:USrv - Endpoint Cache\USrv - Active Registered Users",
                    "\LS:AVMCU - Operations\AVMCU - Number of Users",
                    "\LS:AsMcu - AsMcu Conferences\ASMCU - Connected Users"
                )
            
                $results = get-counter -counter $using:counters | select -expand countersamples | select cookedvalue
            
                $ProcHighMem = (Get-Counter "\Process(*)\Working Set - Private" -ErrorAction SilentlyContinue).CounterSamples | where InstanceName -notmatch '_total|memory compression|idle|system' | select InstanceName, CookedValue | sort CookedValue -Descending | select -First 1
                $ProcHighCpuTime = (Get-Counter "\Process(*)\% Processor Time" -ErrorAction SilentlyContinue).CounterSamples | where InstanceName -notmatch '_total|memory compression|idle|system' | select InstanceName, CookedValue | sort CookedValue -Descending | select -First 1
                $ProcHighRead = (Get-Counter "\Process(*)\IO Read Bytes/sec" -ErrorAction SilentlyContinue).CounterSamples | where InstanceName -notmatch '_total|memory compression|idle|system' | select InstanceName, CookedValue | sort CookedValue -Descending | select -First 1
                $ProcHighWrite = (Get-Counter "\Process(*)\IO Write Bytes/sec" -ErrorAction SilentlyContinue).CounterSamples | where InstanceName -notmatch '_total|memory compression|idle|system' | select InstanceName, CookedValue | sort CookedValue -Descending | select -First 1
                $ProcMostThreads = (Get-Counter "\Process(*)\Thread Count" -ErrorAction SilentlyContinue).CounterSamples | where InstanceName -notmatch '_total|memory compression|idle|system' | select InstanceName, CookedValue | sort CookedValue -Descending | select -First 1
                
                # events
				$today = (Get-Date -Hour 0 -Minute 00 -Second 00)
				$LastHour = (Get-Date).AddHours(-1)					
				$events = Get-WinEvent -FilterHashtable @{LogName = "System","Application","setup"; StartTime = $today; Level = 1,2,3}			
                $eventsSkype = Get-WinEvent -FilterHashtable @{LogName = "Lync Server"; StartTime = $today; Level = 1,2,3}
                $eventsSkype = $eventsSkype | where Id -notlike "20033" | where Id -notlike "32054" | where Id -notlike "32263"
				$eventsSkypeLastHour = $eventsSkype | where TimeCreated -gt $LastHour
				
                # time
                $min = ((get-date) - (gcim Win32_OperatingSystem).LastBootUpTime).totalMinutes;
                $ts = [timespan]::fromminutes($min)
                $TimeWithoutDays = $ts.tostring("hh\:mm")
                $uptime = "$($ts.days):" + $TimeWithoutDays
				
                # disk
                $partitions = Get-PSDrive -Name C,D -ErrorAction SilentlyContinue
				
				# number of cores
				$ThreadCount = (Get-WmiObject -class Win32_processor).NumberOfLogicalProcessors
				
				$object = [PSCustomObject]@{
                    Date        = "{0:dd.MM.yyyy hh:mm}" -f (Get-date)
                    Computer    = hostname
                    UptimeDays  = $uptime
                    'CpuTotal%' = [math]::Round($results[0].CookedValue)
					Cores		= $ThreadCount
                    'CPU1%'     = [math]::Round($results[1].CookedValue)
                    'CPU2%'     = [math]::Round($results[2].CookedValue)
                    'CPU3%'     = [math]::Round($results[3].CookedValue)
                    'CPU4%'     = [math]::Round($results[4].CookedValue)
					MemoryFreeGB        = [math]::Round($results[5].CookedValue,3)
					ServicesRunning		= (Get-Service | where Status -eq "running").count
					NumberOfProcesses	= (Get-Process).count
                    ProcHighCpuTime     = $ProcHighCpuTime.InstanceName
                    'ProcHighCpuTime%'  = [math]::Round(($ProcHighCpuTime.CookedValue)/$ThreadCount)                    
                    ProcHighMem         = $ProcHighMem.InstanceName
                    ProcHighMemGB       = [math]::Round($ProcHighMem.CookedValue/1gb,3)                 
                    ProcHighRead        = $ProcHighRead.InstanceName
                    ProcHighReadMB      = [math]::Round($ProcHighRead.CookedValue/1mb,3)
                    ProcHighWrite       = $ProcHighWrite.InstanceName
                    ProcHighWriteMB     = [math]::Round($ProcHighWrite.CookedValue/1mb,3)                   
                    ProcMostThreads     = $ProcMostThreads.InstanceName
                    ProcMostThreadsCount = $ProcMostThreads.CookedValue
                    DiskFreeC   = [math]::Round($partitions[0].Free/1gb)
                    DiskFreeD   = [math]::Round($partitions[1].Free/1gb)                
                    EventsWarn          = ($events | where Level -eq 3).Count
                    EventsError         = ($events | where Level -eq 2).Count
                    EventsCrit          = ($events | where Level -eq 1).Count
                    EventsWarnSkype     = ($eventsSkype | where Level -eq 3).Count
                    EventsErrorSkype    = ($eventsSkype | where Level -eq 2).Count
                    EventsCritSkype     = ($eventsSkype | where Level -eq 1).Count
                    EventsWarnSkypeLastHour     = ($eventsSkypeLastHour | where Level -eq 3).Count
                    EventsErrorSkypeLastHour    = ($eventsSkypeLastHour | where Level -eq 2).Count
                    EventsCritSkypeLastHour     = ($eventsSkypeLastHour | where Level -eq 1).Count
                    ActiveSkypeUsers    = $results[6].CookedValue   
                    AvMcuSkypeUsers     = $results[7].CookedValue
                    AsMcuSkypeUsers     = $results[8].CookedValue
                }
                
                return $object
            }
        }
    }
}
$results = FLOW -computers $computers | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSSourceJobInstanceId
$results