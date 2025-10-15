
param(
	[string]$Path = "C:\temp\"
)

New-Item -ItemType Directory -Name "DefenderSettings" -Path $Path -ErrorAction SilentlyContinue
$DestinationPath = $($Path + "DefenderSettings\")

Get-MpComputerStatus | out-file $($DestinationPath + "MpComputerStatus.txt")
Get-MpPreference | out-file $($DestinationPath + "MpPreference.txt")

Get-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" | out-file $($DestinationPath + "DefenderAvReg.txt")
Get-Service -Name Sense, WinDefend, MdCoreSvc, WdNisSvc, wscsvc, MDDlpSvc -EA SilentlyContinue | out-file $($DestinationPath + "Services.txt")
Get-CimInstance -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | out-file $($DestinationPath + "AntiVirusProduct.txt")

$asr = Get-MpPreference | select-object "AttackSurface*"
$count = ($asr.AttackSurfaceReductionRules_Actions).count

$asr_config = for ($i = 0; $i -lt $count; $i++){
	
	$RuleId = $asr.AttackSurfaceReductionRules_Ids[$i]
	$Action = $asr.AttackSurfaceReductionRules_Actions[$i]

    IF 	   ($RuleId -eq "56a863a9-875e-4185-98a7-b882c64b5ce5"){$RuleName = "Block abuse of exploited vulnerable signed drivers"}
	ELSEIF ($RuleId -eq "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"){$RuleName = "Block Adobe Reader from creating child processes"}
	ELSEIF ($RuleId -eq "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"){$RuleName = "Block all Office applications from creating child processes"}
	ELSEIF ($RuleId -eq "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"){$RuleName = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"}
	ELSEIF ($RuleId -eq "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"){$RuleName = "Block executable content from email client and webmail"}
	ELSEIF ($RuleId -eq "01443614-cd74-433a-b99e-2ecdc07bfc25"){$RuleName = "Block executable files from running unless they meet a prevalence, age, or trusted list criteria"}
	ELSEIF ($RuleId -eq "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"){$RuleName = "Block execution of potentially obfuscated scripts"}
	ELSEIF ($RuleId -eq "D3E037E1-3EB8-44C8-A917-57927947596D"){$RuleName = "Block JavaScript or VBScript from launching downloaded executable content"}
	ELSEIF ($RuleId -eq "3B576869-A4EC-4529-8536-B80A7769E899"){$RuleName = "Block Office applications from creating executable content"}
	ELSEIF ($RuleId -eq "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"){$RuleName = "Block Office applications from injecting code into other processes"}
	ELSEIF ($RuleId -eq "26190899-1602-49e8-8b27-eb1d0a1ce869"){$RuleName = "Block Office communication applications from creating child processes"}
	ELSEIF ($RuleId -eq "e6db77e5-3df2-4cf1-b95a-636979351e5b"){$RuleName = "Block persistence through WMI event subscription"}
	ELSEIF ($RuleId -eq "d1e49aac-8f56-4280-b9ba-993a6d77406c"){$RuleName = "Block process creations originating from PSExec and WMI commands"}
	ELSEIF ($RuleId -eq "33ddedf1-c6e0-47cb-833e-de6133960387"){$RuleName = "Block rebooting machine in Safe Mode (preview)"}		
	ELSEIF ($RuleId -eq "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"){$RuleName = "Block untrusted and unsigned processes that run from USB"}
	ELSEIF ($RuleId -eq "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"){$RuleName = "Block use of copied or impersonated system tools (preview)"}
	ELSEIF ($RuleId -eq "a8f5898e-1dc8-49a9-9878-85004b8a61e6"){$RuleName = "Block Webshell creation for Servers"}
	ELSEIF ($RuleId -eq "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"){$RuleName = "Block Win32 API calls from Office macro"}
	ELSEIF ($RuleId -eq "c1db55ab-c21a-4637-bb3f-a12568109d35"){$RuleName = "Use advanced protection against ransomware"}
	ELSE { $RuleName = "NONE - check docs and update name" }
		
	[PSCustomObject]@{
		RuleId 	= $RuleId
		Action 	= $Action
		RuleName = $RuleName
	}
}

$asr_config | out-file $($DestinationPath + "DefenderASR.txt")

Compress-Archive -CompressionLevel Fastest -Path "$DestinationPath\*" -DestinationPath $($DestinationPath + ".defender-settings_" + $env:ComputerName + ".zip") -Force
