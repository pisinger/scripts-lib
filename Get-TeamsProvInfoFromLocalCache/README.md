# Get-TeamsProvInfoFromLocalCache
 
This script will give you Teams Client provisioning information from local cache like the following:

```
Ring         : ring2
Region       : pckgsvc-prod-c1-euwe-02
Version      : 1.3.00.33674
Environment  : Production
TenantRegion : amer
NatIpAddr    : 4.4.4.4
UPN          : john@contoso.com
OrgId        : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
TenantId     : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
WebAccountId : Ncisxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ElectronVer  : 8.5.1
WebClientVer : 27/1.0.0.2020120230
UIVersion    : *Lib/UIVersion : 27/1.3.00.33674//
```

Requirement: Powershell 6.0 or above required due to use of "ConvertFrom-Json -AsHashtable"
