# scripts-lib

This repo is used for smaller scripts and functions

**Create-PerfCountersViaWinRM:**
Creating Windows Perf Counters for multiple computers remotely

**Get-TeamsProvInfoFromLocalCache:**
Get some Teams Client provisioning Info from local AppData cache

**Find-PII-Data-in-Files:**
This script does search for PII data in files.

**Get-QuickPerfStatsWin:**
This script returns a quick overview for some perf related counters, the number of error events from today, as well some other stats which may help you to identify a pool node not working as expected. This script was orginally used for a Skype Server environment but can simply adapted for other services too - just change the $Computers array, as well the Event Filter from "Lync Server" used by $eventsSkype to whatever you want.

**Get-SkypeConfLoad:**  
This script will provide you with information about active users being connected to a Skype Front End and being currently in conferences by using Skype Perf Counters. You will also get information about general HealthState per server such as "heavy load", "overloaded", and so on.
