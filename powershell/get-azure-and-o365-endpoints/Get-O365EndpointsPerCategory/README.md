# Get-O365EndpointsPerCategory

This script connects to `M365 Endpoints RestAPI` and keeping an offline version to run the script more efficient and to avoid making same requests to query for same data much often.

The "offline" version of the json file is stored in script execution folder - so the RestAPI will only be queried when this file is older than 1 day, otherwise the existing copy is used.

In addition, you can use the script also to tack for changes within last time delta. For this simply use the `$ChangesWithinLastNumOfDays` param to query for changes.

> <https://aka.ms/o365ips/>

---

**☝ Tested with PowerShell 7 only:**

> <https://aka.ms/GetPowershell/>

---

**Specific switches/params:**

- `[switch]$HttpOnly` = filtering for 80/443 tcp endpoints only
- `[int]$ChangesWithinLastNumOfDays` = query for changes within last x days

**Examples:**

```powershell
.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category Any -Required $True -HttpOnly
.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category Optimize
.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category OptimizeAllow -IPsOnly
.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category OptimizeAllow -IPsOnly -IPVersion IPv4
.\Get-O365EndpointsPerCategory.ps1 -Service Skype -Category OptimizeAllow -URLsOnly
.\Get-O365EndpointsPerCategory.ps1 -Service Exchange -Category Allow -IPversion IPv6 -Required $True
.\Get-O365EndpointsPerCategory.ps1 -Service Any -Category Optimize
.\Get-O365EndpointsPerCategory.ps1 -Category Optimize -IPVersion IPv4
.\Get-O365EndpointsPerCategory.ps1 -Category OptimizeAllow -URLsOnly
.\Get-O365EndpointsPerCategory.ps1 -Service Any -Category Allow -Required $True -IPVersion IPv6
.\Get-O365EndpointsPerCategory.ps1 -Service Common -Category Allow -Required $True -IPversion IPv4
.\Get-O365EndpointsPerCategory.ps1 -SearchURL office.net | ft
```

**Examples for tracking changes:**

```powershell
.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 60 | ft
.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 180  | where serviceArea -like *skype* | ft
(.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 180 | where impact -like *remove*).urls | select -Unique
(.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 180 | where impact -like *add*).urls | select -Unique
(.\Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 360 | where impact -like *add*).ips | select -Unique
```

---

```powershell
Get-O365EndpointsPerCategory.ps1 -Category Optimize -IPVersion IPv4 | ft

serviceArea category required protocol ports               ipsv4                                                                 urls
----------- -------- -------- -------- -----               -----                                                                 ----
Exchange    Optimize     True tcp      80,443              {13.107.6.152/31, 13.107.18.10/31, 13.107.128.0/22, 23.103.160.0/20…} {outlook.office.com, outlook.office365.com}
Skype       Optimize     True udp      3478,3479,3480,3481 {13.107.64.0/18, 52.112.0.0/14, 52.120.0.0/14}
SharePoint  Optimize     True tcp      80,443              {13.107.136.0/22, 40.108.128.0/17, 52.104.0.0/14, 104.146.128.0/17…}  {*.sharepoint.com}
```

```powershell
Get-O365EndpointsPerCategory.ps1 -Service Skype -Category Allow -IPVersion IPv4

serviceArea : Skype
category    : Allow
required    : True
protocol    : tcp
ports       : 80,443
ipsv4       : {13.107.64.0/18, 52.112.0.0/14, 52.120.0.0/14, 52.238.119.141/32…}
urls        : {*.lync.com, *.teams.microsoft.com, teams.microsoft.com}
notes       :

serviceArea : Skype
category    : Allow
required    : True
protocol    : tcp
ports       : 443
ipsv4       : {13.107.64.0/18, 52.112.0.0/14, 52.120.0.0/14, 52.238.119.141/32…}
urls        : {*.broadcast.skype.com, broadcast.skype.com}
notes       :

serviceArea : Skype
category    : Allow
required    : False
protocol    : tcp
ports       : 443
ipsv4       : {13.107.64.0/18, 52.112.0.0/14, 52.120.0.0/14, 52.238.119.141/32…}
urls        : {*.skypeforbusiness.com}
notes       : Teams: Messaging interop with Skype for Business
```

```powershell
Get-O365EndpointsPerCategory.ps1 -ChangesWithinLastNumOfDays 180  | where serviceArea -like *skype* | ft

serviceArea version    category required protocol ports  impact                  ips urls
----------- -------    -------- -------- -------- -----  ------                  --- ----
Skype       2021102900 Default      True tcp      80,443 RemovedIpOrUrl              *.urlp.sfbassets.com
Skype       2021092800 Default      True tcp      80,443 AddedUrl                    *.urlp.sfbassets.com
Skype       2021092800 Default      True tcp      443    RemovedDuplicateIpOrUrl     {*.msecnd.net, ajax.aspnetcdn.com}
Skype       2021092800 Default      True tcp      443    RemovedDuplicateIpOrUrl     amp.azure.net
Skype       2021092800 Default      True tcp      443    RemovedDuplicateIpOrUrl     videoplayercdn.osi.office.net
```
