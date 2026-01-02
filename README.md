<p align="center">
	<img width="1000" height="450" alt="image" src="https://github.com/user-attachments/assets/268f5e51-36c2-4408-9335-597225c99c24" />
</p>

## Background and Overview

We are investigating an intrusion involving a workstation owned by Bill Lumbergh of the Initech Software company. Bill is currently an IT technician hoping to break into the exciting cybersecurity career field. Recently, Bill was looking for free resources for testing his skills in web app penetration testing and used Reddit to try to find a cracked version of a popular software called Burpsuite Pro. Unfortunately, an unsavory Redditor may have sent Bill some malware...

We have acquired key forensic artifacts from Bill’s system to better understand what happened once he ran the malware.

The full walkthrough and investigation steps can be read [here]() <br>

## Tech Stack
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
