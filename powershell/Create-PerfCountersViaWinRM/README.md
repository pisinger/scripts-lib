# Create-PerfCountersViaWinRM
 
This script can be used to deploy perf counters remotely on multiple machines by using WinRM to bypass issues with firewall and rpc when using logman directly.

Change/specify the counters based on your needs - in this example we are using just some Basic System Counters:

```powershell
Function PerfCounterConfig{
    New-Item $ConfigPath -type file -Force | Out-Null	
    #System Performance Counters
    Add-Content $ConfigPath "`"\Processor Information(*)\% Processor Time`""
    Add-Content $ConfigPath "`"\Memory\Available Mbytes`""
    Add-Content $ConfigPath "`"\Network Interface(*)\Output Queue Length`""
    Add-Content $ConfigPath "`"\Network Interface(*)\Outbound Packets Discarded`""
    Add-Content $ConfigPath "`"\Network Interface(*)\Inbound Packets Discarded`""
    Add-Content $ConfigPath "`"\Network Interface(*)\Packets Outbound Discarded`""
    Add-Content $ConfigPath "`"\Network Interface(*)\Packets Received Discarded`""
    Add-Content $ConfigPath "`"\PhysicalDisk(*)\Avg. Disk sec/Read`""
    Add-Content $ConfigPath "`"\PhysicalDisk(*)\Avg. Disk sec/Write`""
}

```