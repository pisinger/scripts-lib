# Get-QuickPerfStatsWin
 
This script returns a quick overview for some perf related counters, the number of error events from today, as well some other stats which may help you to identify a pool node not working as expected. This script was orginally used for a Skype Server environment but can simply adapted for other services too - just change the $Computers array, as well the Event Filter from "Lync Server" used by $eventsSkype to whatever you want. 

Feel free to add more specific counters you are interested in.

Note: WinRM required.

**Examples**
```
$results = .\Get-QuickPerfStatsWin.ps1									# will run on localhost only
$results = .\Get-QuickPerfStatsWin.ps1 -SkypeFrontEnds					# will run against all Skype FEs
$results = .\Get-QuickPerfStatsWin.ps1 -Computers Node1,Node2,Node3		# will run against specific computers

$results | ft computer, net* -AutoSize
$results | ft computer, cpu* -AutoSize
$results | ft computer, proc* -AutoSize
$results | ft computer, event* -AutoSize
$results | ft computer, sys* -AutoSize
```

**Sample Output**
```
Date                     : 4/15/2021 4:14:05 PM
Computer                 : AZ-AG04
SysBootTime              : 4/15/2021 2:33:32 PM
SysOS                    : Microsoft Windows Server 2019 Datacenter
SysBuild                 : 10.0.17763.0
SysLastUpdate            : 4/15/2021 2:35:53 PM
SysModel                 : Virtual Machine
CpuName                  : Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz
CpuMaxClock              : 2295
CpuCores                 : 2
CpuTotal%                : 36
CpuPerCore%              : {48, 25}
MemoryGB                 : 4
MemoryFreeGB             : 0.676
MemoryPagedGB            : 0.688
MemoryUsed%              : 83
ServicesRunning          : 75
ProcessesRunning         : 95
ProcHighCpuTime          : sqlceip
ProcHighCpuTime%         : 0
ProcHighMem              : sqlservr
ProcHighMemGB            : 1.907
ProcHighRead             : microsoftdependencyagent
ProcHighReadMB           : 0.001
ProcHighWrite            : svchost
ProcHighWriteMB          : 0
ProcMostThreads          : sqlservr
ProcMostThreadsCount     : 73
DiskFreeC                : 191
DiskFreeD                : 7
DiskFreeE                : 0
NetPacketsDiscarded      : {0}
NetPacketsSentGbps       : {0.000}
NetPacketsRecvGbps       : {0.000}
EventsLastHour           : 12
EventsCrit               : 1
EventsError              : 122
EventsWarn               : 18
EventTopProvider         : ESENT
EventTopId               : 17806
EventTopCount            : 48
EventsCritSkype          : 0
EventsErrorSkype         : 0
EventsWarnSkype          : 0
EventTopSkype            : 
EventTopSkypeId          : 
EventTopSkypeCount       : 0
EventsCritSkypeLastHour  : 0
EventsErrorSkypeLastHour : 0
EventsWarnSkypeLastHour  : 0
ActiveSkypeUsers         : 
AvMcuSkypeUsers          : 
AsMcuSkypeUsers          : 

Date                     : 4/15/2021 4:14:07 PM
Computer                 : AZ-FE1C
SysBootTime              : 4/15/2021 3:38:32 PM
SysOS                    : Microsoft Windows Server 2019 Datacenter
SysBuild                 : 10.0.17763.0
SysLastUpdate            : 4/15/2021 2:49:12 PM
SysModel                 : Virtual Machine
CpuName                  : Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz
CpuMaxClock              : 2295
CpuCores                 : 2
CpuTotal%                : 1
CpuPerCore%              : {0, 2}
MemoryGB                 : 8
MemoryFreeGB             : 3.519
MemoryPagedGB            : 1.25
MemoryUsed%              : 56
ServicesRunning          : 104
ProcessesRunning         : 133
ProcHighCpuTime          : svchost
ProcHighCpuTime%         : 3.12
ProcHighMem              : w3wp
ProcHighMemGB            : 0.764
ProcHighRead             : sqlservr
ProcHighReadMB           : 0.019
ProcHighWrite            : sqlservr
ProcHighWriteMB          : 0.022
ProcMostThreads          : rtcsrv
ProcMostThreadsCount     : 112
DiskFreeC                : 73
DiskFreeD                : 15
DiskFreeE                : 0
NetPacketsDiscarded      : {0}
NetPacketsSentGbps       : {0.000}
NetPacketsRecvGbps       : {0.000}
EventsLastHour           : 26
EventsCrit               : 0
EventsError              : 27
EventsWarn               : 38
EventTopProvider         : Microsoft-Windows-Perflib
EventTopId               : 1008
EventTopCount            : 24
EventsCritSkype          : 0
EventsErrorSkype         : 103
EventsWarnSkype          : 79
EventTopSkype            : LS User Services
EventTopSkypeId          : 32179
EventTopSkypeCount       : 67
EventsCritSkypeLastHour  : 0
EventsErrorSkypeLastHour : 30
EventsWarnSkypeLastHour  : 21
ActiveSkypeUsers         : 1
AvMcuSkypeUsers          : 0
AsMcuSkypeUsers          : 0
```
