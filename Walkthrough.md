## Table of Contents

1. [Lab Setup]()
2. [Creating Prefetch Timeline]()
3. [Analyzing Prefetch Files]()
4. [Finalized Timeline]()
## Lab Setup

This lab must be conducted on a Windows machine, so I used VMWare to spin up a Windows 11 VM for free.

To setup this lab environment, just run the following script in PowerShell:
```PowerShell
IEX (New-Object Net.Webclient).downloadstring("https://ec-blog.s3.us-east-1.amazonaws.com/DFIR-Lab/PF_Lab/prep_lab.ps1")
```
> This PowerShell script will install Eric Zimmerman's tools, their dependencies, and the Prefetch files used for analysis

If ran successfully: 
- Prefetch Files should be located in: `C:\Cases\Prefetch`
- EZ's tools should be located in: `C:\DFIR_Tools\Zimmerman Tools\net6`

<p align="center">
  <img width="500" height="500" alt="Screenshot_5" src="https://github.com/user-attachments/assets/33ebcb95-ddde-47c0-9147-e6276bd2697a" />
</p>


## Creating Prefetch Timeline

Now that we have all 401 Prefetch files in `C:\Cases\Prefetch`, we must use `PECmd.exe` to parse all of the files into a CSV. This CSV will be transfered into `Timeline Explorer.exe` for further analysis. 

To parse each file, run the following command in PowerShell (Administrative):
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -q -d C:\Cases\Prefetch\ --csv "C:\Cases\Analysis\" --csvf prefetch.csv
```

- `C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe` executes PECmd.exe
- `-q`  prevents full detail dump of each prefetch file (we have 401)
- `-d C:\Cases\Prefetch\` input folder with Prefetch files
- `--csv "C\Cases\Analysis\"` folder location for output files
- `--csvf prefetch.csv` output file name

If ran successfully, you should have two new CSV files:
- `C:\Cases\Analysis\prefetch_Timeline.csv`
- `C:\Cases\Analysis\prefetch.csv`

We can open both of these files in Timeline Explorer to get a better look at the data collected
<p align="center">
  <img width="750" height="750" alt="Screenshot_2" src="https://github.com/user-attachments/assets/918696e3-df49-45a7-80ce-5c5074ba942a" />
</p>

**INSERT IMAGE OF TIMELINE EXPLORER**
ASSORT BY TIMELINE ASCENDING

search for "burp"
look at burp
tag burp
exit to view nearby logs

After viewing executables here are some that I flagged:
<details>
<Summary>Executables Flagged</Summary>

| File Name        | Reasoning                                                                                        |
|------------------|--------------------------------------------------------------------------------------------------|
| `7ZG.EXE`        | 7ZG common file compressor, but was executed right before BURPSUITE.EXE                          |
| `SC.EXE`         | Executed 3s after BURPSUITE.EXE was launched. Could be used for malicious persistence mechanisms |
| `SCHTASKS.EXE`   | Executed 2s after SC.EXE. Could be used as persistence mechanisms through scheduled tasks        |
| `B.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `C.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `P.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `TASKLIST.EXE`   | legitimate executable, but could be used for enumerating device info                             |
| `WHOAMI.EXE`     | legitimate executable, but could be used for enumerating device info                             |
| `FINDSTR.EXE`    | legitimate executable, but could be used for enumerating device info                             |
| `CMD.EXE`        | Could be used to run malicious commands                                                          |
| `NETSTAT.EXE`    | legitimate executable, but could be used for                                                     |
| `RCLONE.EXE`     | Unfamiliar file name and was executed from `Windows\Backup` directory                            |
| `SD.EXE`         | Unfamiliar file name and was executed from `Windows\Backup` directory                            |
| `SYSTEMINFO.EXE` | legitimate executable, but could be used for                                                     |
| `POWERSHELL.EXE` | Could be used to run malicious scripts                                                           |
| `EVERYTHING.EXE` | Unfamliar file name and was executed from `PROGRAM FILES\EVERYTHING` directory                   |
| `IPCONFIG.EXE`   | legitimate executable but could be used for                                                      |
| `ROUTE.EXE`      | legitimate executable, but could be used for                                                     |
| `ARP.EXE`        | legitimate executable, but could be used for                                                     |
</details> 


## Analyzing Prefetch Files
Based on the timeline, we were able to find interesting executables that are worth investigating. We can use `PECmd.exe` to analyze individual Prefetch files to obtain additional program information 

Let's look into the `7ZG.EXE` file since we noticed that was executed prior to the Burpsuite being executed. 
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k burpsuite -f C:\Cases\Prefetch\7ZG.EXE-D9AA3A0B.pf
```

## Finalized Timeline 
