# Find-PII-Data-in-Files
 
This script will search for PII data in files.

```
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory123' -Type EmailAddr
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory123' -Type IpAddrV4 -WriteResultsToFile c:\temp\results.txt
.\Find-PII-Data-in-Files.ps1 -Directory 'D:\Directory123' -Type IpAddrV6 -ListAlsoFileNamesWithoutPII
```

The foreach-loop used for searching files for a match is adapted from here: https://stackoverflow.com/questions/39983462/use-powershell-to-quickly-search-files-for-regex-and-output-to-csv