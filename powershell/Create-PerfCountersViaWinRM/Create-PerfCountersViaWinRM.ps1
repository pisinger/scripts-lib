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

# specify the counters
Function PerfCounterConfig{
	New-Item $ConfigPath -type file -Force | Out-Null	
	# System Performance Counters
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

# call function to create config file on local machine
$ConfigPath = "$env:temp\PerfCounters.config"
PerfCounterConfig
$global:config = Get-Content $ConfigPath

# Specify machines on which you want to configure the PerfCounters
$computers = "node01","node02","node03"

Invoke-Command -ComputerName $computers -ScriptBlock {
	$computer = hostname
	$computer

	# save config in temp file
	$using:config | out-file $using:ConfigPath -Force

	$logmanBin = $env:SystemRoot + "\System32\logman.exe"
		
	# -r = repeat every day
	# -rf = run for 16h
	$logmanSyntax = " create counter KHI -o C:\PerfLogs\KHI_$computer -f csv -si 90 -v mmddhhmm -max 50 -b 09/25/2020 06:00:00 -r -rf 16:00:00 -cf $using:ConfigPath"		
	#$logmanSyntax = " update KHI -b 09/30/2020 06:00:00 -r -rf 16:00:00"
	#$logmanSyntax = " delete KHI"
	#$logmanSyntax = " stop KHI"
	#$logmanSyntax = " start KHI"

	$cmdLine = $logmanBin + $logmanSyntax
	Invoke-Expression $cmdLine

	# remove temp config file
	Remove-Item "$using:ConfigPath" -Force
}

# remove config from local machine
Remove-Item "$ConfigPath" -Force