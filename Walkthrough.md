## Table of Contents

1. [Prefetch Intro]()
2. [Lab Setup]()
3. [Creating Prefetch Timeline]()
4. [Analyzing Prefetch Files]()
5. [Finalized Timeline]()

## Prefetch Intro
## Lab Setup

This lab must be conducted on a Windows machine, so I used VMWare to spin up a Windows 11 VM for free.

To setup this lab environment, just run the following script in PowerShell:
```PowerShell
IEX (New-Object Net.Webclient).downloadstring("https://ec-blog.s3.us-east-1.amazonaws.com/DFIR-Lab/PF_Lab/prep_lab.ps1")
```

> This PowerShell script will install Eric Zimmerman's tools, their dependencies, and the Prefetch files used for analysis

If ran successfully: 
- Prefetch Files should be located at `C:\Cases\Prefetch`
- EZ's tools should be located at `C:\DFIR_Tools\Zimmerman Tools\net6`

![[01 - Projects/Prefetch Analysis Lab/Resources/Screenshot_5.png]]

## Creating Prefetch Timeline

Now that we have all 401 Prefetch files in `C:\Cases\Prefetch`, we must use `PECmd.exe` to parse all of the files into a CSV. This CSV will be transfered into `Timeline Explorer.exe` for further analysis. 

To parse each file, run the following command in PowerShell (Administrative):
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -q -d C:\Cases\Prefetch\ --csv "C:\Cases\Analysis\" --csvf prefetch.csv
```

- `C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe` executes PECmd.exe
- `-q`  prevents full detail dump of each prefetch file (we have over 400 files)
- `-d C:\Cases\Prefetch\` input folder with Prefetch files
- `--csv "C\Cases\Analysis\"` folder location for output files
- `--csvf prefetch.csv` output file name

If ran successfully, you should have two new CSV files:
- `C:\Cases\Analysis\prefetch_Timeline.csv`
- `C:\Cases\Analysis\prefetch.csv`

We can open both of these files in Timeline Explorer to get a better look at the data collected

![[01 - Projects/Prefetch Analysis Lab/Resources/Screenshot_2.png]]

To get a better understanding of what occurred, we can sort in ascending/descending order by clicking **Run Time** column 

We know that Bill was in search of a cracked version of Burpsuite. We can search for the term **burp** to see if any applications were launched on their workstation.

![[01 - Projects/Prefetch Analysis Lab/Resources/Screenshot_3.png]]

We find a single hit seraching this term:
- File Name: `BURPSUITE-PRO-CRACKED.EXE`
- Folder Path: `\USERS\BILL.LUMBERGH\DOWNLOADS\`
- Timestamp: `2024-03-12 18:36:11`

It is evident that Bill downloaded a cracked version of Burpsuite from the internet and was able to launch the application from their downloads folder. 

To keep note of this, we can check this entry under the **tab** column. By clearing the search, Timeline Explorer will showcase nearby executions. 

Now that we know when Bill launched the application, we can search for other artefacts before and after that timestamp.

Here is a list of applications that are suspicious or could be used as a [LOLbin](https://lolbas-project.github.io/):
<details>
<Summary> List of Executables Flagged </Summary>

| File Name      | Reasoning                                                                                        |
|----------------|--------------------------------------------------------------------------------------------------|
| `7ZG.EXE`        | 7Z (GUI) common ZIP extractor, but was executed right before BURPSUITE.EXE                          |
| `SC.EXE`         | Executed 3s after BURPSUITE.EXE was launched. Could be used for malicious persistence mechanisms |
| `SCHTASKS.EXE`   | Executed 2s after SC.EXE. Could be used as persistence mechanisms through scheduled tasks        |
| `B.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `C.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `P.EXE`         | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `TASKLIST.EXE`   | legitimate, but could be used for enumeration                             |
| `WHOAMI.EXE`     | legitimate, but could be used for enumeration                          |
| `FINDSTR.EXE`    | legitimate, but could be used for enumeration                            |
| `CMD.EXE`        | Could be used to run malicious commands                                                          |
| `NETSTAT.EXE`    | legitimate, but could be used for enumeration                                                     |
| `SYSTEMINFO.EXE` | legitimate, but could be used for enumeration                                                    |
| `POWERSHELL.EXE` | Could be used to run malicious script                                                            |
| `RCLONE.EXE`     | Unfamiliar file name and was executed from `Windows\Backup` directory                            |
| `SD.EXE`         | Unfamiliar file name and was executed from `Windows\Backup` directory                            |
| `EVERYTHING.EXE` | Unfamliar file name and was executed from `PROGRAM FILES\EVERYTHING`                             |
| `IPCONFIG.EXE`   | legitimate, but could be used for network discovery                                                    |
| `ROUTE.EXE`      | legitimate, but could be used for network discovery                                                     |
| `ARP.EXE`       | legitimate, but could be used for network discovery                                                     |
</details> 

## Analyzing Prefetch Files
Based on the timeline, we were able to find interesting executables that are worth investigating. We can use `PECmd.exe` to analyze individual Prefetch files to obtain the following information:
- Full System Timestamps
- Execution Count
- Directories Referenced
- Files Referenced

First, let's look into `7ZG.EXE` since it was executed prior to the Burpsuite being executed:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k burpsuite -f C:\Cases\Prefetch\7ZG.EXE-D9AA3A0B.pf
```
- `C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe` executes PECmd.exe
- `-k burpsuite` flag to search burpsuite as an additional keyword
- `-f C:\Cases\Prefetch\7ZG.EXE-D9AA3A0B.pf` input file 

![[01 - Projects/Prefetch Analysis Lab/Resources/Screenshot_4.png]] <br> 
![[01 - Projects/Prefetch Analysis Lab/Resources/Screenshot_6.png]] <br>
![[01 - Projects/Prefetch Analysis Lab/Resources/Screenshot_7.png]] <br>

**How many times did this executable run?** <br>
`Run count: 1` <br>
`Last run: 2024-03-12 18:35:51`

**Executable Full Path** <br>
`\PROGRAM FILES\7-ZIP\7ZG.EXE`

**Keyword Correlation** <br>
`\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.7Z`

**Important Files or Directories Referenced?** <br>
Yes, we see that `7ZG.EXE` was correlated with the archive `\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.7Z`. We can suspect that `BURPSUITE-PRO-CRACKED.EXE` was packaged inside of this archive which allowed the user to bypass security tools. 

---

We can continue this process for all unfamiliar applications that were flagged:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\BURPSUITE-PRO-CRACKED.EXE-EF7051A8.pf
```

**How many times did this executable run?** <br>
`Run Count: 1` <br>
`Last Run: 2024-03-12 18:36:11`

**Executable Full Path** <br>
`\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.EXE`

**Keyword Correlation** <br>
`none`

**Important File or Directory References?** <br>
Nothing too important

---

Next we can examine `B.EXE-3590BF0.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\B.EXE-3590BF0.pf
```

**How many times did this executable run?** <br>
`Run Count: 1` <br>
`Last Run: 2024-03-12 18:55:13`

**Executable Full Path** <br>
`\WINDOWS\TEMP\B.EXE`

**Keyword Correlation** <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP (Keyword True)` <br>
`\WINDOWS\TEMP (Keyword True)` <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP\BHV2ED.TMP (Keyword True)` <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP\CHI3E8.TMP (Keyword True)` <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\TEMP\CHI408.TMP (Keyword True)` <br>
`\WINDOWS\TEMP\1.TXT (Keyword True)`

**Important File or Directory References?** <br>
It would suggest that `B.EXE` is accessing browser history data based on the following references:
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\MICROSOFT\WINDOWS\WEBCACHE\WEBCACHEV01.DAT` <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\GOOGLE\CHROME\USER DATA\DEFAULT\HISTORY` <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA\DEFAULT\HISTORY` <br>
`\USERS\BILL.LUMBERGH\APPDATA\ROAMING\MOZILLA\FIREFOX\PROFILES.INI`

Additionally, `1.TXT` being located in the same directory may indicate a potential output file:
`\WINDOWS\TEMP\1.TXT`

---

Next, we can examine `C.EXE-C6AEC675.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\C.EXE-C6AEC675.pf
```

**How many times did this executable run?** <br>
`Run count: 9` <br>
`Last run: 2024-03-12 19:02:37` <br>
`Other run times: 2024-03-12 19:02:37, 2024-03-12 19:02:01, 2024-03-12 19:02:04, 2024-03-12 19:00:49, 2024-03-12 19:00:51, 2024-03-12 18:57:58, 2024-03-12 18:57:58`

**Executable Full Path** <br>
`\WINDOWS\TEMP\C.EXE`

**Keyword Correlation** <br>
`\WINDOWS\TEMP (Keyword True)` <br>
`\WINDOWS\TEMP\2.TXT (Keyword True)` <br>
`\WINDOWS\TEMP\WCEAUX.DLL (Keyword True)`

**Important File or Directory Reference** <br>
`2.TXT` being located in the same directory may indicate a potential output file:
`\WINDOWS\TEMP\2.TXT`

Doing some research on `WCEAUX.DLL`, it is  a component of Windows Credential Editor (WCE) tool. This has been used to acquire passwords from memory:
`\WINDOWS\TEMP\WCEAUX.DLL`

`WCEAUX.DLL` References:
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/RemoteLogin-WCE.htm?source=post_page-----7bad60c232fe---------------------------------------

----

Next, let's examine `P.EXE-C2093F36.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\P.EXE-C2093F36.pf
```

**How many times did this executable run?** <br>
`Run count: 2` <br>
`Last run: 2024-03-12 19:03:55` <br>
`Other run times: 2024-03-12 19:03:27`

**Executable Full Path** <br>
`\WINDOWS\TEMP\P.EXE`

**Keyword Correlation** <br>
`\WINDOWS\TEMP (Keyword True)`

**Important File or Directory Reference** <br>
Not much aside from `\WINDOWS\TEMP` which is the directory this executbale resides. 

----

Next, let's examine `POWERSHELL.EXE-022A1004.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\POWERSHELL.EXE-022A1004.pf
```

**How many times did this executable run?** <br>
`Run count: 23` <br>
`Last run: 2024-04-13 21:31:28` <br>
`Other run times: 2024-04-13 21:21:23, 2024-04-13 21:21:22, 2024-04-13 20:50:40, 2024-04-13 20:50:40, 2024-03-12 19:26:55, 2024-03-12 19:16:52, 2024-03-12 19:14:15`

**Executable Full Path** <br>
`\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE`

**Keyword Correlation** <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE (Keyword True)` <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA (Keyword True)` <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL (Keyword True)` <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL\MICROSOFT (Keyword True)` <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL\MICROSOFT\WINDOWS (Keyword True)` <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL\MICROSOFT\WINDOWS\POWERSHELL (Keyword True)` <br>
`\WINDOWS\TEMP\_PSSCRIPTPOLICYTEST_2ZE4VHR2.IXM.PS1 (Keyword: True)` <br>
`\WINDOWS\TEMP\_PSSCRIPTPOLICYTEST_X5FEJRPW.EZ3.PSM1 (Keyword: True)` <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL\MICROSOFT\WINDOWS\POWERSHELL\STARTUPPROFILEDATA-NONINTERACTIVE (Keyword: True)` <br>
`\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL\MICROSOFT\WINDOWS\POWERSHELL\MODULEANALYSISCACHE (Keyword: True)` <br>
`\WINDOWS\TEMP\_PSSCRIPTPOLICYTEST_YFY2XGGV.LDY.PS1 (Keyword: True)` <br>
`\WINDOWS\TEMP\_PSSCRIPTPOLICYTEST_UY13XD2B.4AM.PSM1 (Keyword: True)` <br>

**Important Files or Directories  Referenced** <br>
Taking a look at the run times, we can see that PowerShell was ran again within a few milliseconds. This is quite impossible through human interaction, so PowerShell was most likely ran through a script:
`2024-04-13 21:21:23, 2024-04-13 21:21:22` <br>
`2024-04-13 20:50:40, 2024-04-13 20:50:40`

This can be confirmed as PowerShell was executed without user interaction:  `\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL\MICROSOFT\WINDOWS\POWERSHELL\STARTUPPROFILEDATA-NONINTERACTIVE`


Looking even deeper we see that there is a list of potential business documents that were accessed by PowerShell from two different directories. Based on this information, it can be assumed that these documents were copied from Bill's Desktop to a staging directory `C:\Windows\Backup\Logs`:

`\USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\ACCOUNTS-EXPORT-2023-07-24.XLS` <br>
`\WINDOWS\BACKUP\LOGS\ACCOUNTS-EXPORT-2023-07-24.XLS` <br>
`\USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\CYBER-INSURANCE-POLICY-2023.PDF` <br>
`\WINDOWS\BACKUP\LOGS\CYBER-INSURANCE-POLICY-2023.PDF` <br>
`\USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\DC-BACKUPS.ZIP` <br>
`\WINDOWS\BACKUP\LOGS\DC-BACKUPS.ZIP` <br>

`\USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\IT-SYSTEMS-DIAGRAM.PDF` <br>
`\WINDOWS\BACKUP\LOGS\IT-SYSTEMS-DIAGRAM.PDF` <br>

`\USERS\BILL.LUMBERGH\DESKTOP\IT DOCS\OFFSITE BACKUP ARCHITECTURE.PDF` <br>
`\WINDOWS\BACKUP\LOGS\OFFSITE BACKUP ARCHITECTURE.PDF` <br>

With the information that we gathered, we can see if any other executables access any of these files or directories.

---

Next, let's examine `RCLONE.EXE-56772E5D.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup,xls,pdf,zip -f C:\Cases\Prefetch\RCLONE.EXE-56772E5D.pf
```

**How many times did this executable run?** <br>
`Run count: 1` <br>
`Last run: 2024-03-12 19:19:48`

**Executable Full Path** <br>
`\WINDOWS\BACKUP\RCLONE.EXE`

**Keyword Correlation** <br>
`\WINDOWS\BACKUP (Keyword True)` <br>
`\WINDOWS\BACKUP\LOGS (Keyword True)` <br>
`\WINDOWS\BACKUP\RCLONE.CONF (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\1.TXT (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\IT-SYSTEMS-DIAGRAM.PDF (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\2.TXT (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\OFFSITE BACKUP ARCHITECTURE.PDF (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\ACCOUNTS-EXPORT-2023-07-24.XLS (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\CYBER-INSURANCE-POLICY-2023.PDF (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\DC-BACKUPS.ZIP (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\LSASS.DMP (Keyword: True)`

**Important File or Directory Reference** <br>
Using the new keywords we were able to find new hits. The directory `\WINDOWS\BACKUP\LOGS` appears to be a staging location for potential data exfiltration.

In this Backup directory, we can see a configuration file for `RCLONE.EXE`: 
`\WINDOWS\BACKUP\RCLONE.CONF`

Additionally, we can see memory dump file, `LSASS.DMP (Local Security Authority Subsystem Service)`. Doing some research, LSASS Memory is commonly used for credential dumping. 

References:
- https://attack.mitre.org/techniques/T1003/001/

----
Since all of our previous hits were in the `WINDOWS\BACKUP` directory, we can narrow our keywords to just `backup`

Next, let's examine `SD.EXE-A541D1D9.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup -f C:\Cases\Prefetch\SD.EXE-A541D1D9.pf
```

**How many times did this executable run?** <br>
`Run count: 1` <br>
`Last run: 2024-03-12 19:26:11`

**Executable Full Path** <br>
`\WINDOWS\BACKUP\SD.EXE`

**Keyword Correlation** <br>
`\WINDOWS\BACKUP (Keyword True)` <br>
`\WINDOWS\BACKUP\LOGS (Keyword True)` <br>
`\WINDOWS\BACKUP\LOGS\1.TXT (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\2.TXT (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\ACCOUNTS-EXPORT-2023-07-24.XLS (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\CYBER-INSURANCE-POLICY-2023.PDF (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\DC-BACKUPS.ZIP (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\IT-SYSTEMS-DIAGRAM.PDF (Keyword: True)` <br>
`\WINDOWS\BACKUP\LOGS\LSASS.DMP (Keyword: True)`

**Important File or Directory Reference** <br>
Again, files in `\WINDOWS\BACKUP` were accessed which was pretty similar to `RCLONE.EXE`


## Finalized Timeline <br>
Now that we've gathered a ton of information from our previous steps, we can refer back to Timeline Explorer to make sure we found all related executions. 

Remember we still have `prefetech.csv` which we can use to deep dive into all important files and locations observed from our findings. 

Let's search for the following in Timeline Explorer:
- `burpsuite`
- `\b.exe` 
- `\c.exe`
- `\p.exe`
- `RCLONE`
- `\sd.exe`
- `WCEAUX`
- `lsass`
- `\Windows\Backup`

When searching `\Windows\Backup`, we found `SYSTEMINFO.EXE` accessing this directory, which is pretty unusual. 

Let's go back to the command line to learn more about this prefetch file: 
```PowerShell
PS C:\Users\JohnDoe> C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup -f C:\Cases\Prefetch\SYSTEMINFO.EXE-644FF4E7.pf
```

**How many times did this executable run?** <br>
`Run count: 13` <br>
`Last run: 2024-04-13 21:31:26` <br>
`Other run times: 2024-04-13 21:21:20, 2024-04-13 20:50:38, 2024-03-12 19:26:53, 2024-03-12 19:26:53, 2024-03-12 19:16:51, 2024-03-12 19:16:51, 2024-03-12 19:11:24`

**Executable Full Path** <br>
`\WINDOWS\SYSTEM32\SYSTEMINFO.EXE`

**Keyword Correlation** <br>
`\WINDOWS\BACKUP (Keyword True)` <br>
`\WINDOWS\BACKUP\INFO.TXT`

**Important File or Directory Reference** <br>
There is a new file `INFO.TXT` that was discovered in the staging directory that was not referenced by previous executables. 

This is quite odd behavior from SYSTEMINFO.EXE. The attacker must have used this to dump information into this text file. 
