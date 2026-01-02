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
Analysis of the collected artifacts revealed a cracked version of Burp Suite Pro was downloaded and executed by the user, initiating a multi-stage intrusion on the system.

Following execution, several unfamiliar binaries were launched from temporary directories, and native Windows utilities were abused to perform system reconnaissance and credential harvesting. Sensitive business documents were later copied into a staging directory which was then accessed by a cloud synchronization tool, strongly suggesting that sensitive data was exfiltrated to an external cloud service. The intrusion concluded with additional activity consistent with post-exfiltration cleanup and anti-forensic behavior.

The findings confirm a deliberate compromise resulting in credential exposure and potential data loss. 

A detailed walkthrough of these findings can be read [here]()

<p align="center">
	<img width="1000" height="800" alt="Screenshot 2026-01-01 at 7 41 54 PM" src="https://github.com/user-attachments/assets/749c9f33-15e4-4f61-8856-986108457f22" />
</p>

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
- Malware infection
- Data theft or data exfiltration

## Credit
Thank you to Eric Capuano for creating this [Prefetch Analysis Lab](https://blog.ecapuano.com/p/prefetch-analysis-lab)
