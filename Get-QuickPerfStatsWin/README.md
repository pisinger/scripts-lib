# Get-QuickPerfStatsWin
 
This script returns a quick overview for some perf related counters, the number of error events from today, as well some other stats which may help you to identify a pool node not working as expected. This script was orginally used for a Skype Server environment but can simply adapted for other services too - just change the $Computers array, as well the Event Filter from "Lync Server" used by $eventsSkype to whatever you want. 

Feel free to add more specific counters you are interested in.

**Examples**
```
Date                     : 18.03.2021 03:05
Computer                 : AZ-FE1D
UptimeDays               : 0:00:22
CpuTotal%                 : 75
Cores                    : 2
CPU1%                    : 75
CPU2%                    : 75
CPU3%                    : 0
CPU4%                    : 0
MemoryFreeGB             : 3437
ServicesRunning          : 96
NumberOfProcesses        : 112
ProcHighCpuTime          : tiworker
ProcHighCpuTime%         : 47
ProcHighMem              : tiworker
ProcHighMemGB            : 0.394
ProcHighRead             : msmpeng
ProcHighReadMB           : 36.671
ProcHighWrite            : msmpeng
ProcHighWriteMB          : 0.57
ProcMostThreads          : sqlservr
ProcMostThreadsCount     : 71
DiskFreeC                : 76
DiskFreeD                : 15
EventsWarn               : 8
EventsError              : 12
EventsCrit               : 0
EventsWarnSkype          : 7
EventsErrorSkype         : 36
EventsCritSkype          : 0
EventsWarnSkypeLastHour  : 7
EventsErrorSkypeLastHour : 36
EventsCritSkypeLastHour  : 0
ActiveSkypeUsers         : 0
AvMcuSkypeUsers          : 0
AsMcuSkypeUsers          : 0

Date                     : 18.03.2021 03:05
Computer                 : AZ-FE1C
UptimeDays               : 0:00:22
CpuTotal%                 : 98
Cores                    : 2
CPU1%                    : 98
CPU2%                    : 99
CPU3%                    : 0
CPU4%                    : 0
MemoryFreeGB             : 2195
ServicesRunning          : 103
NumberOfProcesses        : 133
ProcHighCpuTime          : mrt
ProcHighCpuTime%         : 47
ProcHighMem              : sqlservr
ProcHighMemGB            : 0.339
ProcHighRead             : mrt
ProcHighReadMB           : 6.702
ProcHighWrite            : tiworker
ProcHighWriteMB          : 0.934
ProcMostThreads          : rtcsrv
ProcMostThreadsCount     : 112
DiskFreeC                : 74
DiskFreeD                : 15
EventsWarn               : 9
EventsError              : 5
EventsCrit               : 0
EventsWarnSkype          : 23
EventsErrorSkype         : 19
EventsCritSkype          : 0
EventsWarnSkypeLastHour  : 23
EventsErrorSkypeLastHour : 19
EventsCritSkypeLastHour  : 0
ActiveSkypeUsers         : 1
AvMcuSkypeUsers          : 0
AsMcuSkypeUsers          : 0
```
