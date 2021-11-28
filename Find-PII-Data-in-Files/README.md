# Find-PII-Data-in-Files
 
This script does search for PII data in files.

```powershell
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type EmailAddr
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type IpAddrV4 -WriteResultsToFile c:\temp\results.txt
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type IpAddrV6 -ShowAlsoFileNamesWithoutPII
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type StringToSearch -SearchString john.doe -ShowMatches
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory' -Type StringToSearch -SearchString "1234-0000-1234" -ShowMatches
```

The foreach-loop used for searching files for a match is adapted from here: https://stackoverflow.com/questions/39983462/use-powershell-to-quickly-search-files-for-regex-and-output-to-csv