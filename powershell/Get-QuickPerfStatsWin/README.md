# Get-QuickPerfStatsWin
 
This script returns a quick overview for some perf related counters, the number of error events from today, as well some other stats which may help you to identify a pool node not working as expected. This script was orginally used for a Skype Server environment but can simply adapted for other services too - just change the $Computers array, as well the Event Filter from "Lync Server" used by $eventsSkype to whatever you want. 

Feel free to add more specific counters you are interested in.

Note: WinRM required.

**Examples**
```powershell
$results = .\Get-QuickPerfStatsWin.ps1						# will run on localhost only
$results = .\Get-QuickPerfStatsWin.ps1 -SkypeFrontEnds				# will run against all Skype FEs
$results = .\Get-QuickPerfStatsWin.ps1 -Computers Node1,Node2,Node3		# will run against specific computers

$results | ft computer, net* -AutoSize
$results | ft computer, cpu* -AutoSize
$results | ft computer, proc* -AutoSize
$results | ft computer, event* -AutoSize
$results | ft computer, sys* -AutoSize
```

**Sample Output**
```powershell
Date                       : 4/22/2021 12:15:58 PM
Computer                   : AZ-AG04
SysBootTime                : 4/22/2021 11:03:51 AM
SysOS                      : Microsoft Windows Server 2019 Datacenter
SysBuild                   : 10.0.17763.0
SysLastUpdate              : 4/15/2021 2:35:53 PM
SysModel                   : Virtual Machine
CpuName                    : Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz
CpuMaxClock                : 2295
CpuCores                   : 2
CpuTotal%                  : 36
CpuPerCore%                : {48, 25}
MemoryGB                   : 8
MemoryFreeGB               : 4.47
MemoryPagedGB              : 1.25
MemoryUsed%                : 44
ServicesRunning            : 77
ProcessesRunning           : 97
ProcHighCpuTime            : microsoftdependencyagent
ProcHighCpuTime%           : 0.78
ProcHighMem                : sqlservr
ProcHighMemGB              : 1.997
ProcHighRead               : svchost
ProcHighReadMB             : 0
ProcHighWrite              : sqlservr
ProcHighWriteMB            : 0
ProcMostThreads            : sqlservr
ProcMostThreadsCount       : 70
DiskFreeC                  : 191
DiskFreeD                  : 15
DiskFreeE                  : 0
NetPacketsDiscarded        : {0}
NetPacketsSentGbps         : {0.000}
NetPacketsRecvGbps         : {0.000}
EventsLastHour             : 6
EventsCrit                 : 0
EventsError                : 22
EventsWarn                 : 2
EventTopProvider           : ESENT
EventTopId                 : 490
EventTopCount              : 12
EventsServiceCrit          : 0
EventsServiceError         : 0
EventsServiceWarn          : 0
EventTopService            :
EventTopServiceId          :
EventTopServiceCount       : 0
EventsServiceLastHourCrit  : 0
EventsServiceLastHourError : 0
EventsServiceLastHourWarn  : 0
SkypeUsersActive           :
SkypeUsersAvMcu            :
SkypeUsersAsMcu            :

Date                       : 4/22/2021 12:20:40 PM
Computer                   : DE-FE1C
SysBootTime                : 4/22/2021 10:31:58 AM
SysOS                      : Microsoft Windows Server 2019 Datacenter
SysBuild                   : 10.0.17763.0
SysLastUpdate              : 4/15/2021 2:48:42 PM
SysModel                   : Virtual Machine
CpuName                    : Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz
CpuMaxClock                : 2594
CpuCores                   : 2
CpuTotal%                  : 2
CpuPerCore%                : {2, 2}
MemoryGB                   : 8
MemoryFreeGB               : 3.246
MemoryPagedGB              : 1.25
MemoryUsed%                : 59
ServicesRunning            : 112
ProcessesRunning           : 164
ProcHighCpuTime            : explorer
ProcHighCpuTime%           : 0
ProcHighMem                : w3wp
ProcHighMemGB              : 1.023
ProcHighRead               : rtcsrv
ProcHighReadMB             : 0.005
ProcHighWrite              : sqlservr
ProcHighWriteMB            : 0.021
ProcMostThreads            : rtcsrv
ProcMostThreadsCount       : 110
DiskFreeC                  : 85
DiskFreeD                  : 15
DiskFreeE                  : 0
NetPacketsDiscarded        : {0, 0}
NetPacketsSentGbps         : {0.075, 0.075}
NetPacketsRecvGbps         : {0.027, 0.024}
EventsLastHour             : 2
EventsCrit                 : 0
EventsError                : 16
EventsWarn                 : 9
EventTopProvider           : Service Control Manager
EventTopId                 : 7031
EventTopCount              : 9
EventsServiceCrit          : 0
EventsServiceError         : 510
EventsServiceWarn          : 84
EventTopService            : LS File Transfer Agent Service
EventTopServiceId          : 1046
EventTopServiceCount       : 277
EventsServiceLastHourCrit  : 0
EventsServiceLastHourError : 254
EventsServiceLastHourWarn  : 24
SkypeUsersActive           : 2
SkypeUsersAvMcu            : 0
SkypeUsersAsMcu            : 0
```
