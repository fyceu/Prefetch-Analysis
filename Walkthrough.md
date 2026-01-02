## Table of Contents

1. [Lab Setup](https://github.com/fyceu/Prefetch-Analysis/blob/main/Walkthrough.md#lab-setup)
2. [Creating Prefetch Timeline](https://github.com/fyceu/Prefetch-Analysis/blob/main/Walkthrough.md#creating-prefetch-timeline)
3. [Analyzing Prefetch Files](https://github.com/fyceu/Prefetch-Analysis/blob/main/Walkthrough.md#analyzing-prefetch-files)
4. [Drafting a Timeline](https://github.com/fyceu/Prefetch-Analysis/blob/main/Walkthrough.md#drafting-a-timeline-)
5. [Finalized Timeline](https://github.com/fyceu/Prefetch-Analysis/blob/main/Walkthrough.md#finalized-timeline)

## Lab Setup
This lab must be conducted on a Windows machine, so I used VMWare to spin up a Windows 11 VM for free.

To setup this lab environment, just run the following script in PowerShell:
```PowerShell
IEX (New-Object Net.Webclient).downloadstring("https://ec-blog.s3.us-east-1.amazonaws.com/DFIR-Lab/PF_Lab/prep_lab.ps1")
```
<p align="center">
    <img width="750" height="400" src="https://github.com/fyceu/Prefetch-Analysis/blob/WIP/2025-12-26%2022-16-09_3%20(1).gif">
</p>

> This PowerShell script will install Eric Zimmerman's tools, their dependencies, and the Prefetch files used for analysis


If ran successfully: 
- Prefetch Files should be located at `C:\Cases\Prefetch`
- EZ's tools should be located at `C:\DFIR_Tools\Zimmerman Tools\net6`

<p align="center">
  <img width="1000" height="750" alt="Screenshot_5" src="https://github.com/user-attachments/assets/b53e16b0-a38a-4d3f-a1da-799e9f349679" />
</p>

## Creating Prefetch Timeline

Now that we have all 401 Prefetch files in `C:\Cases\Prefetch`, we must use `PECmd.exe` to parse all of the files into a CSV. This CSV will be transfered into `Timeline Explorer` for further analysis. 

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

<p align="center">
  <img width="1477" height="886" alt="Screenshot_2" src="https://github.com/user-attachments/assets/1c329182-a4be-4391-af36-d761cefaa486" />
</p>

To get a better understanding of what occurred, we can sort the entries in ascending/descending order by clicking on the **Run Time** column 

We know that Bill was in search of a cracked version of Burpsuite. We can search for the term **burp** to see if any applications were launched on their workstation.

<p align="center">
  <img width="1478" height="303" alt="Screenshot_3" src="https://github.com/user-attachments/assets/126ecba5-8653-4fb6-b77b-8158686c0d51" />
</p>

Searching this shows a single hit:
- File Name: `BURPSUITE-PRO-CRACKED.EXE`
- Folder Path: `\USERS\BILL.LUMBERGH\DOWNLOADS\`
- Run Time: `2024-03-12 18:36:11`

It is evident that Bill downloaded a cracked version of Burpsuite from the internet and was able to launch the application from their downloads folder.
To keep note of this, we can check this entry under the **tab** column. By clearing the search, Timeline Explorer will showcase nearby executions. 

Now that we know when Bill launched the application, we can search for other artefacts before and after that timestamp.

Below is a list of applications that are suspicious or could be used as a [LOLbin](https://lolbas-project.github.io/)
<details>
<Summary><strong><u>List of Executables Flagged</u></strong></Summary>
  
| File Name        | Reasoning                                                                                        |
|----------------  |--------------------------------------------------------------------------------------------------|
| `7ZG.EXE`        | 7Z (GUI) common ZIP extractor, but was executed right before BURPSUITE.EXE                       |
| `SC.EXE`         | Executed 3s after BURPSUITE.EXE was launched. Could be used for malicious persistence mechanisms |
| `SCHTASKS.EXE`   | Executed 2s after SC.EXE. Could be used as persistence mechanisms through scheduled tasks        |
| `B.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `C.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `P.EXE`          | Unfamiliar file name and was executed from `Windows\Temp` directory                              |
| `TASKLIST.EXE`   | legitimate, but could be used for enumeration                                                    |
| `WHOAMI.EXE`     | legitimate, but could be used for enumeration                                                    |
| `FINDSTR.EXE`    | legitimate, but could be used for enumeration                                                    |
| `CMD.EXE`        | Could be used to run malicious commands                                                          |
| `NETSTAT.EXE`    | legitimate, but could be used for enumeration                                                    |
| `SYSTEMINFO.EXE` | legitimate, but could be used for enumeration                                                    |
| `POWERSHELL.EXE` | Could be used to run malicious scripts                                                           |
| `RCLONE.EXE`     | Unfamiliar file name and was executed from `Windows\Backup` directory                            |
| `SD.EXE`         | Unfamiliar file name and was executed from `Windows\Backup` directory                            |
| `EVERYTHING.EXE` | Unfamliar file name and was executed from `PROGRAM FILES\EVERYTHING`                             |
| `IPCONFIG.EXE`   | legitimate, but could be used for network discovery                                              |
| `ROUTE.EXE`      | legitimate, but could be used for network discovery                                              |
| `ARP.EXE`        | legitimate, but could be used for network discovery                                              |

</details> 

## Analyzing Prefetch Files
Based on the timeline, we were able to find interesting executables that are worth investigating. We can use `PECmd.exe` to analyze individual Prefetch files to obtain the following information:
- Full System Timestamps (8 most recent)
- Execution Count
- Directories Referenced
- Files Referenced

First, let's look into `7ZG.EXE` since it was executed right before Burpsuite was executed:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k burpsuite -f C:\Cases\Prefetch\7ZG.EXE-D9AA3A0B.pf
```
- `C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe` executes PECmd.exe
- `-k burpsuite` flag to search burpsuite as an additional keyword
- `-f C:\Cases\Prefetch\7ZG.EXE-D9AA3A0B.pf` input file 


<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1312" height="591" alt="Screenshot_4" src="https://github.com/user-attachments/assets/7e26fd39-170a-43b9-9ef5-d388aad8d05e" />
  <img width="1532" height="348" alt="Screenshot_6" src="https://github.com/user-attachments/assets/f5b3581a-c879-46ef-a5ac-1c2dbbf24686" />
  <img width="1547" height="1038" alt="Screenshot_7" src="https://github.com/user-attachments/assets/2d42e94a-f966-4c59-8d50-37f7c8202184" />
</p>

</details>

**How many times did this executable run?** <br>
`Run count: 1` <br>
`Last run: 2024-03-12 18:35:51`

**Executable Full Path** <br>
`\PROGRAM FILES\7-ZIP\7ZG.EXE`

**Keyword Correlation** <br>
`\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.7Z`

**Observations** <br>
We see that `7ZG.EXE` was correlated with the archive `\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.7Z`. We can suspect that `BURPSUITE-PRO-CRACKED.EXE` was packaged inside of this archive to evade security tools from marking this download as malicious

---

We can continue this process for all unfamiliar applications that we previously flagged:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\BURPSUITE-PRO-CRACKED.EXE-EF7051A8.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>

<p align="center">
  <img width="1541" height="771" alt="Screenshot_8" src="https://github.com/user-attachments/assets/d14e36e3-d765-4d08-9b3b-e25a0afc5a7c" />
  <img width="1542" height="1070" alt="Screenshot_9" src="https://github.com/user-attachments/assets/9197f090-0eb0-4ff1-b8df-1494718c741d" />
</p>

</details>


**How many times did this executable run?** <br>
`Run Count: 1` <br>
`Last Run: 2024-03-12 18:36:11`

**Executable Full Path** <br>
`\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.EXE`

**Keyword Correlation** <br>
`none`

**Observations** <br>
There doesn't seem to be anything important that stands out with the directories or files referenced by this application. 

---

Next we can examine `B.EXE-3590BF0.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\B.EXE-3590BF0.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1537" height="1167" alt="Screenshot_13" src="https://github.com/user-attachments/assets/5d842a96-779f-4ad0-b177-dcab17065f1b" />
  <img width="1538" height="1098" alt="Screenshot_14" src="https://github.com/user-attachments/assets/be3affca-6cf4-44e4-80ef-c99feef62948" />
</p>

</details>

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
`\WINDOWS\TEMP\1.TXT (Keyword True)` <br>

**Observations**<br>
Though not marked by any keywords, I would suggest that `B.EXE` is accessing browser history data based on the following references:
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\MICROSOFT\WINDOWS\WEBCACHE\WEBCACHEV01.DAT` <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\GOOGLE\CHROME\USER DATA\DEFAULT\HISTORY` <br>
`\USERS\BILL.LUMBERGH\APPDATA\LOCAL\MICROSOFT\EDGE\USER DATA\DEFAULT\HISTORY` <br>
`\USERS\BILL.LUMBERGH\APPDATA\ROAMING\MOZILLA\FIREFOX\PROFILES.INI`<br>

Additionally, we discover `1.TXT` being located in `\WINDOWS\TEMP` which may indicate a potential output file.

---

Next, we can examine `C.EXE-C6AEC675.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\C.EXE-C6AEC675.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1545" height="1163" alt="Screenshot_15" src="https://github.com/user-attachments/assets/46a64f2d-d42d-4887-a9a7-d9101da13157" />
  <img width="1540" height="1160" alt="Screenshot_16" src="https://github.com/user-attachments/assets/b69c12cd-968d-4bad-a2e1-297560c60c62" />
</p>

</details>

**How many times did this executable run?** <br>
`Run count: 9` <br>
`Last run: 2024-03-12 19:02:37` <br>
`Other run times: 2024-03-12 19:02:37, 2024-03-12 19:02:01, 2024-03-12 19:02:04, 2024-03-12 19:00:49, 2024-03-12 19:00:51, 2024-03-12 18:57:58, 2024-03-12 18:57:58`

**Executable Full Path** <br>
`\WINDOWS\TEMP\C.EXE`

**Keyword Correlation** <br>
`\WINDOWS\TEMP (Keyword True)` <br>
`\WINDOWS\TEMP\2.TXT (Keyword True)` <br>
`\WINDOWS\TEMP\WCEAUX.DLL (Keyword True)` <br>

**Observations** <br>
Again, we discover `2.TXT` and it being located in `\WINDOWS\TEMP\` may indicate a potential output file.

There is a hit on a new file, `WCEAUX.DLL`, which has not been accessed by any previous executable. After doing a quick google search on `WCEAUX.DLL`, it is a component of Windows Credential Editor (WCE) tool which has been used to acquire passwords from memory.

`WCEAUX.DLL` References:
- [https://jpcertcc.github.io/ToolAnalysisResultSheet/details/RemoteLogin-WCE.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/RemoteLogin-WCE.htm?source=post_page-----7bad60c232fe---------------------------------------)

----

Next, let's examine `P.EXE-C2093F36.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k wceaux -f C:\Cases\Prefetch\P.EXE-C2093F36.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1438" height="1076" alt="Screenshot_23" src="https://github.com/user-attachments/assets/4ecb8ddd-1acf-4ea0-aca3-bced3fe29e16" />
</p>

</details>

**How many times did this executable run?** <br>
`Run count: 2` <br>
`Last run: 2024-03-12 19:03:55` <br>
`Other run times: 2024-03-12 19:03:27`

**Executable Full Path** <br>
`\WINDOWS\TEMP\P.EXE`

**Keyword Correlation** <br>
`\WINDOWS\TEMP (Keyword True)`

**Observations** <br>
Not much aside from `\WINDOWS\TEMP` which is the directory this executbale resides. 

----

Next, let's examine `POWERSHELL.EXE-022A1004.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -f C:\Cases\Prefetch\POWERSHELL.EXE-022A1004.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1545" height="1195" alt="Screenshot_19" src="https://github.com/user-attachments/assets/6acbf11d-b18f-4fa2-9141-5b91e47360df" />
  <img width="1542" height="908" alt="Screenshot_20" src="https://github.com/user-attachments/assets/dbbea6c0-639b-4148-8862-3ed762f59e9f" />
  <img width="1537" height="1194" alt="Screenshot_21" src="https://github.com/user-attachments/assets/a4016a55-0124-4b40-a60a-1e38d224adf5" />
</p>
  
</details>

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

**Observations** <br>
Taking a look at the run times, we can see that PowerShell was ran again within a few milliseconds. This is quite impossible through human interaction, so PowerShell was most likely ran through a script <br>
`2024-04-13 21:21:23, 2024-04-13 21:21:22` <br>
`2024-04-13 20:50:40, 2024-04-13 20:50:40`

This can be confirmed as PowerShell was executed without user interaction:  `\WINDOWS\SYSTEM32\CONFIG\SYSTEMPROFILE\APPDATA\LOCAL\MICROSOFT\WINDOWS\POWERSHELL\STARTUPPROFILEDATA-NONINTERACTIVE`

Looking even deeper we see that there is a list of potential business documents that were accessed by PowerShell from two different directories. Based on this information, it can be assumed that these documents were copied from Bill's Desktop to a staging directory `C:\Windows\Backup\Logs` <br>
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

With this information, we should keep an eye out if any other executable references these files or directory.

---

Next, let's examine `RCLONE.EXE-56772E5D.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup,xls,pdf,zip -f C:\Cases\Prefetch\RCLONE.EXE-56772E5D.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1029" height="610" alt="Screenshot_24" src="https://github.com/user-attachments/assets/319eb41a-02e6-4321-8dc2-d2389ce50564" />
  <img width="1087" height="1089" alt="Screenshot_25" src="https://github.com/user-attachments/assets/0e157586-a896-44b6-8273-94251725463e" />
</p>
  
</details>

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

**Observations** <br>
After a quick google search, I found that `RCLONE` is a legitimate command-line program used to manage and sync cloud files.

The presence of  `\WINDOWS\BACKUP\RCLONE.conf` in the same directory as `RCLONE.EXE`, is quite significant as it may provide details such as:
- cloud providers
- authentication methods 
- destination paths

With `RCLONE.EXE` accessing the files copied over to `\WINDOWS\BACKUP\LOGS` strongly indicates this directory was used as a staging location prior to potential data exfiltration.  

Additionally, the discovery of `LSASS.DMP (Local Security Authority Subsystem Service)` within this same directory is of importance. Doing some research, LSASS Memory is commonly used for credential dumping. The presence of this file suggests credential harvesting occurred. 

References:
- [RCLONE](https://rclone.org/docs/)
- [Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

----

Since all of our previous hits were in the `WINDOWS\BACKUP` directory, we can narrow our keywords to just `backup`

Next, let's examine `SD.EXE-A541D1D9.pf`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup -f C:\Cases\Prefetch\SD.EXE-A541D1D9.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1129" height="764" alt="Screenshot_26" src="https://github.com/user-attachments/assets/20808427-971f-4c1b-88d1-b4f712b4ba50" />
  <img width="1644" height="761" alt="Screenshot_27" src="https://github.com/user-attachments/assets/d973748f-e22b-461b-9f1e-4b7db74403d4" />
</p>

</details>


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

**Observations** <br>
Again, files in `\WINDOWS\BACKUP` were accessed which was pretty similar to `RCLONE.EXE`


## Drafting a Timeline <br>
Now that we've gathered a ton of information from our previous steps, we can refer back to Timeline Explorer to make sure we found all related executions. 

Remember we still have `prefetech.csv` which we can use to deep dive into all important files and locations observed from our findings. 

Let's search for the following terems in Timeline Explorer to see if we missed anything:
- `burpsuite`
- `\b.exe` 
- `\c.exe`
- `\p.exe`
- `RCLONE`
- `\sd.exe`
- `WCEAUX`
- `lsass.dmp`
- `\Windows\Backup`

When searching for other Prefetch files that relate to `lsass.dmp`, there was one prefetch that we missed `RUNDLL32.EXE-9698B75.pf`:.
<p align="center">
  <img width="1575" height="433" alt="Screenshot_30" src="https://github.com/user-attachments/assets/2d11597f-ca44-47f1-ae2b-97ebe1254f71" />
</p>

Before we tag this, let's take a closer look using `PECmd`:
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup,bill -f C:\Cases\Prefetch\RUNDLL32.EXE-9698B756.pf
```

<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1171" height="1149" alt="Screenshot_32" src="https://github.com/user-attachments/assets/2ffa9e87-e536-49e7-b703-234b8f314568" />
  <img width="1282" height="1152" alt="Screenshot_33" src="https://github.com/user-attachments/assets/edad91c3-75dc-41d4-a871-fbaf09ff845b" />
  <img width="1283" height="1149" alt="Screenshot_34" src="https://github.com/user-attachments/assets/ee8eba4f-f761-4a84-80d2-407772b6a545" />
</p>

</details>

**How many times did this executable run?** <br>
`Run count: 1` <br>
`Last run: 2024-03-12 19:06:13`

**Executable Full Path** <br>
`\WINDOWS\SYSTEM32\RUNDLL32.EXE`

**Keyword Correlation** <br>
`\WINDOWS\BACKUP (Keyword True)` <br>
`\WINDOWS\BACKUP\LOGS (Keyword True)` <br>
`\WINDOWS\BACKUP\LOGS\LSASS.DMP (Keyword True)`

**Observations** <br>
`RUNDLL32.EXE` is a legitimate windows binary that is commonly exploited by attackers to execute functions from DLL files. Since this was seen accessing `\WINDOWS\BACKUP\LOGS\LSASS.DMP`, `RUNDLL32` could have been used during credential dumping.

Let's go back to `Timeline Explorer` and tag this prefetch.

 ---

Again, When searching the term `\Windows\Backup`, we found another executable, `SYSTEMINFO.EXE` accessing this directory.

<p align="center">
  <img width="1573" height="422" alt="Screenshot_31" src="https://github.com/user-attachments/assets/d8211ebf-5b02-43ff-bde2-a6b92c7e3fe2" />
</p>

Let's check out this prefetch file to see what else `SYSTEMINFO.EXE` accessed: 
```PowerShell
C:\DFIR_Tools\ZimmermanTools\net6\PECmd.exe -k backup -f C:\Cases\Prefetch\SYSTEMINFO.EXE-644FF4E7.pf
```
<details>
<summary><strong> Output Screenshots </strong></summary>
<p align="center">
  <img width="1250" height="624" alt="Screenshot_28" src="https://github.com/user-attachments/assets/09a44fa3-0983-46a6-bc93-91ee1aaef695" />
  <img width="858" height="783" alt="Screenshot_29" src="https://github.com/user-attachments/assets/beb6b23a-472d-4f64-a33a-4b521dcfd1fb" />
</p>

</details>

**How many times did this executable run?** <br>
`Run count: 13` <br>
`Last run: 2024-04-13 21:31:26` <br>
`Other run times: 2024-04-13 21:21:20, 2024-04-13 20:50:38, 2024-03-12 19:26:53, 2024-03-12 19:26:53, 2024-03-12 19:16:51, 2024-03-12 19:16:51, 2024-03-12 19:11:24`

**Executable Full Path** <br>
`\WINDOWS\SYSTEM32\SYSTEMINFO.EXE`

**Keyword Correlation** <br>
`\WINDOWS\BACKUP (Keyword True)` <br>
`\WINDOWS\BACKUP\INFO.TXT (keyword True)`

**Important File or Directory Reference** <br>
There is a new file `INFO.TXT` that was discovered in the staging directory that was not referenced by previous executables. 

This is quite odd behavior from `SYSTEMINFO.EXE`. The attacker must have used this to dump information into this text file. 

---

## Finalized Timeline
Now that we have every important even tagged, we can clear our search and filter for tagged only events. Sorting by **Last Ran** will provide us a rough timeline of what occurred.

<p align="center">
  <img width="1568" height="608" alt="Screenshot_22" src="https://github.com/user-attachments/assets/9fd37204-d860-4b37-a7b2-13c5e1216ef1" />
</p>

### Initial Access - Archive Extracted
Bill downloaded an archive file from the internet containing the cracked version of Burpsuite. He utilized 7ZG.exe to extract the contents of the archive:
- Earliest Timestamp: `2024-03-12 18:35:51`
- File Name: `BURPSUITE-PRO-CRACKED.7Z`
- Full Path: `\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.7Z`
- Prefetch File: `7ZG.EXE-D9AA3A0B.pf`

### Malicious Executable Launched
Shortly after the extraction, the Bill launched the extracted Burpsuite file directly from thier downloads folder:
- Earliest Timestmap: `2024-03-12 18:36:11`
- File Name: `BURPSUITE-PRO-CRACKED.EXE`
- Full Path: `\USERS\BILL.LUMBERGH\DOWNLOADS\BURPSUITE-PRO-CRACKED.EXE`
- Prefetch File: `BURPSUITE-PRO-CRACKED.EXE-EF7051A8.pf`

### Post-Execution Activity
Roughly 20 minutes after the applicaiton was launched, multiple suspicious executables began running from the `\WINDOWS\TEMP` directory. `B.EXE` was seen accessing browser history from Chrome, Edge, and Firefox, indicating reconnaissance and enumeration.
- Earliest Timestamp: `2024-03-12 18:55:13`
- File Name: `B.EXE`
- Full Path: `\WINDOWS\TEMP\B.EXE`
- Prefetch File: `B.EXE-3590BF0.pf`

### Credential Access
Another executable, `C.EXE`, is seen launching in Bill's `\WINDOWS\TEMP` directory. `C.EXE` is seen referencing `WCEAUX.DLL`, strongly suggesting crednetial dumping from memory.
- Earliest Timestamp: `2024-03-12 18:57:58`
- File Name: `C.EXE`
- Full Path: `\WINDOWS\TEMP\C.EXE`
- Prefetch File: `C.EXE-C6AEC675.pf`

### Additional TEMP Execution
Though no references to previous taggged artefacts, `P.EXE` was seen being executed in `WINDOWS\TEMP`
  - Earliest Timestamp: `2024-03-12 19:03:27`
  - File Name: `P.EXE`
  - Full Path: `\WINDOWS\TEMP\P.EXE`
  - Prefetch File: `P.EXE-C2093F36.pf`

### Credential Dumping
`RUNDLL32.EXE` accessed `\WINDOWS\BACKUP\LOGS\LSASS.DMP`, indicating it was likely used in part of a LSASS Memory Dumping process. This is also the first time a malicious file accessed the staging directory `\WINDOWS\BACKUP\LOGS`, classifying `RUNDLL32.EXE` as a LOLbin.
- Earliest Timestamp: `2024-03-12 19:06:13`
- File Name: `RUNDLL32.EXE`
- Full Path: `\WINDOWS\SYSTEM32\RUNDLL32.EXE`
- Prefetch File: `RUNDLL32.EXE-9698B756.pf`

### Host Reconnaissance
`SYSTEMINFO.EXE` was seen executing multiple times. With `\WINDOWS\BACKUP\INFO.TXT` being referenced, it suggests that `SYSTEMINFO.EXE` was being used for host reconnaissance. 
- Earliest Timestamp: `2024-03-12 19:11:24`
- File Name: `SYSTEMINFO.EXE`
- Full Path: `\WINDOWS\SYSTEM32\SYSTEMINFO.EXE`
- Prefetch File: `SYSTEMINFO.EXE-644FF4E7.pf`

### Malicious Scripting <br> 
PowerShell is seen copying multiple sensitive business doucments from Bill's Desktop into the primary staging directory `\WINDOWS\BACKUP\LOGS`
- Earliest Timestamp: `2024-03-12 19:14:15`
- File Name: `POWERSHELL.EXE`
- Full Path: `\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE`
- Prefetch File: `POWERSHELL.EXE-022A1004.pf`

### Data Exfiltration <br>
`RCLONE.EXE`, a cloud syncing and file management tool, is seen executing within the staging directory, `\WINDOWS\BACKUP`. The presence of its configuration file, `RCLONE.conf`, within this directory strongly indicates data exfiltration to an external cloud service.
- Earliest Timestamp: `2024-03-12 19:19:48`
- File Name: `RCLONE.EXE`
- Full Path; `\WINDOWS\BACKUP\RCLONE.EXE`
- Prefetch File: `RCLONE.EXE-56772E5D.pf`

### Post-Exfiltration Clean Up <br>
`SD.EXE` accesssed the same staging directory and files as `RCLONE.EXE`. With this being the last suspicious execution and common attacker techniques, `SD.EXE` was most likely used for anti-forensic purposes, removing evidence after successful exfiltration. 
- Earliest Timestamp: `2024-03-12 19:26:11`
- File Name: `SD.EXE`
- Full Path: `\WINDOWS\BACKUP\SD.EXE`
- Prefetch File: `SD.EXE-A541D1D9.pf`
