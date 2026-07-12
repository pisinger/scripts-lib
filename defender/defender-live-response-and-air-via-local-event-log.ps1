# https://pisinger.github.io/posts/defender-endpoint-air-local-senseir-events/

<#
	Get-DefenderEventsSenseAutomatedInvestigation |  Select-Object TimeCreated, Id, LevelDisplayName, Message
	Get-DefenderEventsSenseAutomatedInvestigation -ActionReportOnly | Select-Object TimeCreated, Id, Message
	
	TimeCreated          Action                                               Source  ResultCode
	-----------          ------                                               ------  ----------
	21/06/2026 21:22:55  GetTcpConnectionListAction                           AIR     0x0
	21/06/2026 21:22:56  GetDriverListAction                                  AIR     0x0
	21/06/2026 21:22:58  GetServiceListAction                                 AIR     0x0
	21/06/2026 21:23:43  GetProcessListAction                                 AIR     0x0
	21/06/2026 21:24:12  ReadProcessMemoryAction                              AIR     0x0
	21/06/2026 21:33:56  PersistenceCheckAction                               AIR     0x0
	21/06/2026 21:33:57  GetRecentlyExecutedFilesAction                       AIR     0x0
	21/06/2026 21:34:04  GetRecentlyCreatedOrModifiedExecutableFileListAction AIR     0x0
#>

function Get-DefenderEventsSenseIR {
    param (
        [string]$Pattern,
        [switch]$Filtered
    )

    $ids = 1..5

    $events = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashTable @{
        ProviderName = "Microsoft-Windows-SenseIR"
    }

    if ($Filtered) {
        $events = $events | Where-Object Id -notin $ids
    }

    if ($Pattern) {
        $events = $events | Where-Object Message -like "*$Pattern*"
    }

    return $events
}

function Get-DefenderSenseIRActionSource {
    param (
        [Parameter(Mandatory)]
        [string]$ActionId
    )

    if ($ActionId -like "iaid_*") {
        return "AIR"
    }

    if ($ActionId -like "eeaid_*") {
        return "Network Discovery"
    }

    if ($ActionId -match "^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$") {
        return "Live Response"
    }

    return "Unknown"
}

function Get-DefenderEventsSenseAutomatedInvestigation {
    param (
        [switch]$ActionReportOnly
    )

    $ids = 7, 11
    $events = Get-DefenderEventsSenseIR | Where-Object Id -in $ids

    if ($ActionReportOnly) {
        $events = $events | Where-Object Id -eq 11
    }

    return $events
}

Get-DefenderEventsSenseAutomatedInvestigation -ActionReportOnly |
    ForEach-Object {
        $actionId = [regex]::Match($_.Message, "Action ID: (?<id>[^,]+)").Groups["id"].Value

        [pscustomobject]@{
            TimeCreated = $_.TimeCreated
            Action      = [regex]::Match($_.Message, "action (?<action>[^.]+)\.").Groups["action"].Value
            ActionId    = $actionId
            Source      = Get-DefenderSenseIRActionSource -ActionId $actionId
            ResultCode  = [regex]::Match($_.Message, "upload result code: (?<code>\S+)").Groups["code"].Value
        }
    } | Sort-Object TimeCreated
	