# Get-Conf-Load-per-FE-via-PerfCounters
 
This script will provide you with information about active users being connected to a Skype Front End and being currently in conferences by using Skype Perf Counters. You will also get information about general HealthState per server such as "heavy load", "overloaded", and so on.

**Sample Output**

```powershell
Computer            : FE08
CPU%                : 14
RamFree             : 8858
ActiveUsers         : 929
SipConnections      : 1002
ImMcuConfs          : 33
ImMcuUsers          : 36
AvMcuConfs          : 39
AVMcuUsers          : 73
AsMcuConfs          : 41
AsMcuUsers          : 67
VbssMcuConfs        : 12
VbssMcuUsers        : 72
ImMcuHealthState    : 0
DataMcuHealthState  : 0
AvMcuHealthState    : 0
AsMcuHealthState    : 0
AvMcuHealthGlobal   : 1
AsMcuHealthGlobal   : 1
McusNormalState     : 137
McusOverloaded      : 0
MediationCallsOut   : 4
MediationCallsIn    : 9
MediationHealth     : 1
```