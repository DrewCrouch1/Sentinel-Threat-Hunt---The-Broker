# Sentinel-Threat-Hunt---The-Broker
Broker Threat Hunt – Full Step-by-Step Investigation

Author: Andrew Crouch
Platform: Microsoft Defender for Endpoint + Microsoft Sentinel
Environment: Azure VM Lab
Focus: Threat Hunting, Detection Engineering, Incident Reconstruction

## Investigation Overview

This project documents a complete threat hunt following a malicious executable disguised as a PDF:

daniel_richardson_cv.pdf.exe

The investigation reconstructs the attack chain from:

Initial user execution

Command & Control communication

Credential theft via reflective loading

Lateral movement

Sensitive data access

Data staging

Anti-forensics activity

The investigation is presented exactly as it was hunted — pivot by pivot.

## Initial Lead – User & Device Pivot

Starting Point

User: Sophie.Turner

Device: AS-PC1

<img width="732" height="496" alt="image" src="https://github.com/user-attachments/assets/7a616bcd-66e8-40b7-8bea-fa2a99855279" />

KQL Used
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where AccountName =~ "Sophie.Turner"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
Result

Discovered:

daniel_richardson_cv.pdf.exe

The file executable file was disquised as a PDF.

<img width="1413" height="373" alt="Screenshot 2026-02-23 205049" src="https://github.com/user-attachments/assets/decf47b6-5fdf-4bb8-acd0-cce2ace35996" />

## Was It User-Driven Execution?
KQL Used
DeviceProcessEvents
| where InitiatingProcessSHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, InitiatingProcessParentFileName, InitiatingProcessIntegrityLevel
Finding

Parent Process: explorer.exe

Integrity Level: High

Conclusion:

The user double-clicked the file.

<img width="1410" height="394" alt="Screenshot 2026-02-23 221245" src="https://github.com/user-attachments/assets/6ee73dc6-ec66-41ee-b1b3-20df71e37ca1" />

Initial Access Vector: Phishing / Social Engineering

## Post-Execution Enumeration

Immediately after execution, the payload performed:

whoami

hostname

net user

net localgroup administrators

net view

Interpretation

Standard discovery activity (MITRE T1082, T1018).

<img width="1407" height="396" alt="Screenshot 2026-02-23 223450" src="https://github.com/user-attachments/assets/7d51840b-290f-4cfa-b694-7a004774cf78" />

## Command & Control Confirmation
KQL Used
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| project Timestamp, RemoteIP, RemoteUrl
Result

Outbound HTTPS connection to:

104.21.30.237

sync.cloud-endpoint.net

Conclusion:

Active command-and-control communication confirmed.

<img width="944" height="185" alt="Screenshot 2026-02-26 211146" src="https://github.com/user-attachments/assets/e0f0d65a-5aec-42c0-973d-27fed116bd17" />

<img width="1469" height="69" alt="Screenshot 2026-02-24 222655" src="https://github.com/user-attachments/assets/d5ca3db7-56a2-44ea-9fa3-e6344b19a8db" />

## How Did the EXE Get There?

This was a key investigative pivot.

Attempted Query
DeviceFileEvents
| where FileName == "daniel_richardson_cv.pdf.exe"
Finding

No FileCreated event found.

However:

Process execution logs exist.

Network telemetry exists.

Conclusion

The file was placed on disk before Defender onboarding.

This explains the absence of file creation telemetry.

This was validated by:

Timeline comparison

Execution telemetry existing without creation telemetry

<img width="1428" height="221" alt="Screenshot 2026-02-24 224033" src="https://github.com/user-attachments/assets/41c3c268-a409-4075-9db5-05454aee6d4f" />

## Persistence

CertUtil is used to install AnyDesk.exe on "as-pc1", "as-pc2" and "as-srv." 

Conclusion:

This was likely used to blend into normal traffic since AnyDesk is legitamte software with encrypted communication. AnyDesk offers full GUI control, the ability to extract and import files, and persistence if the malware is quarantined.

<img width="1410" height="218" alt="Screenshot 2026-02-23 224055" src="https://github.com/user-attachments/assets/796abbf5-c479-474e-92ed-a28518b632ea" />

A scheduled task named “MicrosoftEdgeUpdateCheck” is created to run the previously downloaded payload “RuntimeBroker.exe” daily at 3:00 a.m. with the highest privileges. This task creation is forced to override any existing task with the same name. The hash of "RunTimeBroker.exe" matches the hash of the initial payload daniel_richardson_cv.pdf.exe.

<img width="1469" height="69" alt="Screenshot 2026-02-24 222655" src="https://github.com/user-attachments/assets/00cbf497-0c46-4492-818d-445dcdfd7692" />

<img width="1428" height="221" alt="Screenshot 2026-02-24 224033" src="https://github.com/user-attachments/assets/dbe699a1-767f-4283-8a90-aae6a4721555" />

<img width="1475" height="73" alt="Screenshot 2026-02-24 220037" src="https://github.com/user-attachments/assets/30740e41-92b9-4ab5-b610-903b75b9a721" />

## Credential Theft Detection
HKLM System and Sam are saved to C:\Users\Public.

These files were likely extracted to crack the local accounts and password hashes offline.

<img width="1355" height="122" alt="Screenshot 2026-02-23 225627" src="https://github.com/user-attachments/assets/ba9a58ba-eec4-488b-aaf0-6179f765ce23" />

KQL Used
DeviceEvents
| where ActionType == "ClrUnbackedModuleLoaded"
| project Timestamp, InitiatingProcessFileName, AdditionalFields
Finding
Module: SharpChrome
Process: notepad.exe
ActionType: ClrUnbackedModuleLoaded
Interpretation

SharpChrome (credential harvesting tool) was loaded directly into memory.

No disk artifact required.

Credential theft via reflective .NET assembly loading confirmed.

<img width="1372" height="68" alt="Screenshot 2026-02-24 210822" src="https://github.com/user-attachments/assets/815168eb-3008-419b-a642-66734895322a" />

<img width="1341" height="380" alt="Screenshot 2026-02-24 212418" src="https://github.com/user-attachments/assets/cb01240a-00b3-41c2-a811-46dd203adf61" />

<img width="1320" height="236" alt="Screenshot 2026-02-24 211929" src="https://github.com/user-attachments/assets/2cf8f44f-6819-4d3a-9359-c298df770c95" />

## Lateral Movement Attempts

Observed attempts:

WMIC remote execution

PsExec execution

Successful pivot via mstsc.exe

Creation of "svc_backup" account that was added to the administrator group

Outcome:

Pivot to AS-PC2 with user "david.mitchell"

Administrator account activated

Password modified

<img width="1345" height="274" alt="Screenshot 2026-02-23 225815" src="https://github.com/user-attachments/assets/cb247ca2-4e81-4073-834b-83cb1ec5cef2" />

<img width="1322" height="136" alt="Screenshot 2026-02-24 205653" src="https://github.com/user-attachments/assets/74b5c85e-6c64-47e2-a7ef-6eff569bc1a4" />

<img width="1120" height="60" alt="Screenshot 2026-02-24 205858" src="https://github.com/user-attachments/assets/f661aea5-dd31-471d-a4c2-09dc24394e8e" />

<img width="1292" height="211" alt="Screenshot 2026-02-24 210149" src="https://github.com/user-attachments/assets/5ed1a768-06f6-494b-9203-c8b2727922a1" />

<img width="1081" height="139" alt="Screenshot 2026-02-24 214820" src="https://github.com/user-attachments/assets/f6a005c8-0ccc-4647-841f-771e221f4052" />

## Sensitive Payroll File Access

Target file:

\\AS-SRV\Payroll\BACS_Payments_Dec2025.ods
KQL Used
DeviceFileEvents
| where FileName contains "BACS_Payments_Dec2025"
Critical Artifact
.~lock.BACS_Payments_Dec2025.ods#
Interpretation

LibreOffice lock file confirms:

The file was opened for editing, not just viewing.

<img width="1208" height="104" alt="Screenshot 2026-02-24 215408" src="https://github.com/user-attachments/assets/8a7ed0f7-386c-425b-90ec-ede4394c05b4" />

<img width="1413" height="345" alt="Screenshot 2026-02-24 231308" src="https://github.com/user-attachments/assets/dddcc783-f019-4de4-a0d7-bf7336ef6112" />

## Data Staging

Archive created:

Shares.7z

Tool used:

7zG.exe
Conclusion:

Data compressed prior to potential exfiltration.

<img width="1404" height="74" alt="Screenshot 2026-02-24 223140" src="https://github.com/user-attachments/assets/1e8a6004-f5ac-4ec1-b2f7-429c265c97a2" />

MITRE T1560 – Archive Collected Data

## Anti-Forensics Activity
KQL Used
DeviceEvents
| where ActionType contains "Cleared"
Result

Logs cleared via:

Security

System

Application

Windows PowerShell

Using:

wevtutil cl
Conclusion

Indicator removal on host (MITRE T1070).

<img width="1255" height="247" alt="Screenshot 2026-02-24 210451" src="https://github.com/user-attachments/assets/9b3f6512-6540-43f9-98e4-5c9c1c27e455" />

## MITRE ATT&CK Mapping
Tactic	Technique
Initial Access	T1566 – Phishing
Execution	T1059 – Command & Scripting Interpreter
Discovery	T1082 – System Information Discovery
Persistence T1053 - Scheduled Task/Job
Credential Access	T1003 – Credential Dumping
Lateral Movement	T1021 – Remote Services
Collection	T1560 – Archive Collected Data
Defense Evasion	T1070 – Indicator Removal
Command & Control	T1071 – Application Layer Protocol

## Full Attack Chain Summary

User executed malicious disguised PDF.

Payload established HTTPS C2.

Enumeration conducted.

Persistense achieved.

SharpChrome loaded reflectively into memory.

Credentials harvested.

Lateral movement attempted via WMIC/PsExec.

Successful pivot via RDP.

Sensitive payroll file accessed and edited.

Data archived into Shares.7z.

Logs cleared to cover tracks.

## Skills Demonstrated

Advanced KQL threat hunting

Process tree reconstruction

Reflective DLL detection

Cross-device correlation

Attack chain reconstruction

MITRE ATT&CK mapping

Defender onboarding gap analysis

## Key Investigative Insight

The absence of file creation telemetry, combined with execution and network logs, revealed a critical gap:

The malicious file existed before Defender onboarding.

Recognizing telemetry gaps versus attacker tradecraft is a core detection engineering skill.

## Portfolio Purpose

This project demonstrates the ability to:

Follow an intrusion end-to-end

Pivot intelligently across telemetry tables

Validate assumptions with data

Identify stealth techniques

Reconstruct adversary behavior
