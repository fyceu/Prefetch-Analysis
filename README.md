<p align="center">
	<img width="900" height="450" alt="image" src="https://github.com/user-attachments/assets/021db897-4baf-40d8-bab5-f30d58cc83d5" />
</p>

## Background and Overview

We are investigating an intrusion involving a workstation owned by Bill Lumbergh of the Initech Software company. Bill is currently an IT technician hoping to break into the exciting cybersecurity career field. Recently, Bill was looking for free resources for testing his skills in web app penetration testing and used Reddit to try to find a cracked version of a popular software called Burpsuite Pro. Unfortunately, an unsavory Redditor may have sent Bill some malware...

We have acquired key forensic artifacts from Bill’s system to better understand what happened once he ran the malware.

The full walkthrough and investigation steps can be read [here]() <br>

## Tech Stack
<img width="70" height="70" alt="image" src="https://github.com/user-attachments/assets/69213894-7080-4063-8d1b-45e07dd20413" />
<img width="70" height="70" alt="image" src="https://github.com/user-attachments/assets/ecd8816b-ea1a-41ff-8a48-2feb8925ef89" />
<img width="70" height="70" alt="image" src="https://github.com/user-attachments/assets/fc7d980d-917f-4cca-a18a-4c5acf496988" />
<img width="70" height="70" alt="image" src="https://github.com/user-attachments/assets/72f8d3a9-0b95-43ac-9666-754feaf516d9" />

- VMWare 
- Windows 11 VM 
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)
	- PECmd
	- Timeline Explorer
- PowerShell

## Executive Summary

## Recommendations
Based on the findings of this investigation, the following security recommendations are provided to help prevent similar incidents and improve detection capabilities

### Endpoint Security
Block unapproved/unauthorized third-party tools (cracked software, cloud sync tools)

Implement Applicaiton Execution Controls using tools such as `Applocker` to prevent the execution of files and scripts from commonly abused directories:
- `Downloads`
- `TEMP`
- `AppData`

### SIEM Monitoring
Monitor and create alerts for the following PowerShell activity:
- PowerShell continuously executed within milliseconds
- Commands executed without user interaction
- PowerShell accessing sensitive files or system directories

### Security Awareness
Reinforce Initech's Acceptable Use Policies and emphasize clear consequences for policy violations

Educate employees on the risks of downloading cracked or unauthorized software:
- malware infection
- data theft or data exfiltration
