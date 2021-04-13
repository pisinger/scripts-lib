# Get-QuickPerfStatsWin
 
This script returns a quick overview for some perf related counters, the number of error events from today, as well some other stats which may help you to identify a pool node not working as expected. This script was orginally used for a Skype Server environment but can simply adapted for other services too - just change the $Computers array, as well the Event Filter from "Lync Server" used by $eventsSkype to whatever you want. 

Feel free to add more specific counters you are interested in.

**Examples**
```
Date                     : 4/13/2021 4:47:56 PM
Computer                 : AZ-AG04
BootTime                 : 4/13/2021 3:21:19 PM
OS                       : Microsoft Windows Server 2019 Datacenter
Model                    : Virtual Machine
CoreName                 : Intel(R) Xeon(R) Platinum 8171M CPU @ 2.60GHz
MaxClock                 : 2095
Cores                    : 2
CpuTotal%                : 1
CpuPerCore%              : {2, 0}
MemoryFreeGB             : 4.274
MemoryPagedGB            : 1.25
MemoryUsed%              : 47
ServicesRunning          : 77
ProcessesRunning         : 97
ProcHighCpuTime          : msmpeng
ProcHighCpuTime%         : 0.78
ProcHighMem              : sqlservr
ProcHighMemGB            : 2.235
ProcHighRead             : microsoftdependencyagent
ProcHighReadMB           : 0
ProcHighWrite            : svchost
ProcHighWriteMB          : 0
ProcMostThreads          : sqlservr
ProcMostThreadsCount     : 68
DiskFreeC                : 192
DiskFreeD                : 15
DiskFreeE                : 0
EventsLastHour           : 6
EventsCrit               : 0
EventsError              : 24
EventsWarn               : 3
EventMostProvider        : ESENT
EventMostId              : 490
EventMostCount           : 12
EventsCritSkype          : 0
EventsErrorSkype         : 0
EventsWarnSkype          : 0
EventMostSkype           : 
EventMostSkypeId         : 
EventMostSkypeCount      : 0
EventsCritSkypeLastHour  : 0
EventsErrorSkypeLastHour : 0
EventsWarnSkypeLastHour  : 0
ActiveSkypeUsers         : 
AvMcuSkypeUsers          : 
AsMcuSkypeUsers          : 

Date                     : 4/13/2021 4:47:57 PM
Computer                 : AZ-FE1D
BootTime                 : 4/13/2021 3:22:34 PM
OS                       : Microsoft Windows Server 2019 Datacenter
Model                    : Virtual Machine
CoreName                 : Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz
MaxClock                 : 2295
Cores                    : 2
CpuTotal%                : 23
CpuPerCore%              : {28, 18}
MemoryFreeGB             : 4.94
MemoryPagedGB            : 1.25
MemoryUsed%              : 38
ServicesRunning          : 94
ProcessesRunning         : 109
ProcHighCpuTime          : clsagent
ProcHighCpuTime%         : 14.81
ProcHighMem              : svchost
ProcHighMemGB            : 0.686
ProcHighRead             : sqlservr
ProcHighReadMB           : 0.026
ProcHighWrite            : sqlservr
ProcHighWriteMB          : 0.184
ProcMostThreads          : sqlservr
ProcMostThreadsCount     : 74
DiskFreeC                : 80
DiskFreeD                : 15
DiskFreeE                : 0
EventsLastHour           : 4
EventsCrit               : 0
EventsError              : 16
EventsWarn               : 8
EventMostProvider        : Service Control Manager
EventMostId              : 7024
EventMostCount           : 8
EventsCritSkype          : 0
EventsErrorSkype         : 69
EventsWarnSkype          : 12
EventMostSkype           : LS Health Agent
EventMostSkypeId         : 56011
EventMostSkypeCount      : 40
EventsCritSkypeLastHour  : 0
EventsErrorSkypeLastHour : 34
EventsWarnSkypeLastHour  : 5
ActiveSkypeUsers         : 2
AvMcuSkypeUsers          : 2
AsMcuSkypeUsers          : 0
```
