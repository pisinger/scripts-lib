# Get-QuickPerfStatsWin
 
This script returns a quick overview for some perf related counters, the number of error events from today, as well some other stats which may help you to identify a pool node not working as expected. This script was orginally used for a Skype Server environment but can simply adapted for other services too - just change the $Computers array, as well the Event Filter from "Lync Server" used by $eventsSkype to whatever you want. 

Feel free to add more specific counters you are interested in.

**Examples**
```
Date                     : 19.03.2021 19:34
Computer                 : AZ-FE1D
UptimeDays               : 0d:00:25
CoreName                 : Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz
MaxClock                 : 2295
Cores                    : 2
CpuTotal%                : 75
CPU1%                    : 75
CPU2%                    : 75
CPU3%                    : 0
CPU4%                    : 0
MemoryFreeGB             : 4.43
MemoryPagedGB            : 1.25
MemoryUsed%              : 45
ServicesRunning          : 102
NumberOfProcesses        : 136
ProcHighCpuTime          : fabric
ProcHighCpuTime%         : 3
ProcHighMem              : w3wp
ProcHighMemGB            : 0.652
ProcHighRead             : sqlservr
ProcHighReadMB           : 0.013
ProcHighWrite            : w3wp
ProcHighWriteMB          : 0.005
ProcMostThreads          : rtcsrv
ProcMostThreadsCount     : 131
DiskFreeC                : 73
DiskFreeD                : 15
EventsWarn               : 26
EventsError              : 29
EventsCrit               : 0
EventsWarnSkype          : 92
EventsErrorSkype         : 139
EventsCritSkype          : 0
EventsWarnSkypeLastHour  : 20
EventsErrorSkypeLastHour : 10
EventsCritSkypeLastHour  : 0
ActiveSkypeUsers         : 0
AvMcuSkypeUsers          : 0
AsMcuSkypeUsers          : 0

Date                     : 19.03.2021 19:34
Computer                 : AZ-AG04
UptimeDays               : 0d:03:47
CoreName                 : Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz
MaxClock                 : 2295
Cores                    : 2
CpuTotal%                : 14
CPU1%                    : 16
CPU2%                    : 12
CPU3%                    : 0
CPU4%                    : 0
MemoryFreeGB             : 0.868
MemoryPagedGB            : 0.688
MemoryUsed%              : 78
ServicesRunning          : 75
NumberOfProcesses        : 95
ProcHighCpuTime          : powershell
ProcHighCpuTime%         : 5
ProcHighMem              : sqlservr
ProcHighMemGB            : 1.841
ProcHighRead             : microsoftdependencyagent
ProcHighReadMB           : 0.002
ProcHighWrite            : sqlceip
ProcHighWriteMB          : 0
ProcMostThreads          : sqlservr
ProcMostThreadsCount     : 69
DiskFreeC                : 189
DiskFreeD                : 7
EventsWarn               : 16
EventsError              : 79
EventsCrit               : 0
EventsWarnSkype          : 0
EventsErrorSkype         : 0
EventsCritSkype          : 0
EventsWarnSkypeLastHour  : 0
EventsErrorSkypeLastHour : 0
EventsCritSkypeLastHour  : 0
ActiveSkypeUsers         : 
AvMcuSkypeUsers          : 
AsMcuSkypeUsers          : 

```
