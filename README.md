# Sentinel-Threat-Hunt---The-Broker
Broker Threat Hunt – Full Step-by-Step Investigation

Author: Andrew Crouch
Platform: Microsoft Defender for Endpoint + Microsoft Sentinel
Environment: Azure VM Lab
Focus: Threat Hunting, Detection Engineering, Incident Reconstruction

🧭 Investigation Overview

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

1️⃣ Initial Lead – User & Device Pivot

Starting Point

User: Sophie.Turner

Device: AS-PC1

KQL Used
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where AccountName =~ "Sophie.Turner"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
Result

Discovered:

daniel_richardson_cv.pdf.exe

The file appeared to be a resume but was actually an executable.

2️⃣ Was It User-Driven Execution?
KQL Used
DeviceProcessEvents
| where InitiatingProcessSHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, InitiatingProcessParentFileName, InitiatingProcessIntegrityLevel
Finding

Parent Process: explorer.exe

Integrity Level: High

Conclusion

The user double-clicked the file.

Initial Access Vector: Phishing / Social Engineering

3️⃣ Post-Execution Enumeration

Immediately after execution, the payload performed:

whoami

hostname

net user

net localgroup administrators

net view

Interpretation

Standard discovery activity (MITRE T1082, T1018).

4️⃣ Command & Control Confirmation
KQL Used
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| project Timestamp, RemoteIP, RemoteUrl
Result

Outbound HTTPS connection to:

104.21.30.237

sync.cloud-endpoint.net

Conclusion

Active command-and-control communication confirmed.

5️⃣ How Did the EXE Get There?

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

6️⃣ Reflective Credential Theft Detection
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

7️⃣ Lateral Movement Attempts

Observed attempts:

WMIC remote execution

PsExec execution

Successful pivot via mstsc.exe

Outcome

Pivot to AS-PC2

Administrator account activated

Password modified

8️⃣ Sensitive Payroll File Access

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

9️⃣ Data Staging

Archive created:

Shares.7z

Tool used:

7zG.exe
Conclusion

Data compressed prior to potential exfiltration.

MITRE T1560 – Archive Collected Data

🔟 Anti-Forensics Activity
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

🧠 MITRE ATT&CK Mapping
Tactic	Technique
Initial Access	T1566 – Phishing
Execution	T1059 – Command & Scripting Interpreter
Discovery	T1082 – System Information Discovery
Credential Access	T1003 – Credential Dumping
Lateral Movement	T1021 – Remote Services
Collection	T1560 – Archive Collected Data
Defense Evasion	T1070 – Indicator Removal
Command & Control	T1071 – Application Layer Protocol
🧩 Full Attack Chain Summary

User executed malicious disguised PDF.

Payload established HTTPS C2.

Enumeration conducted.

SharpChrome loaded reflectively into memory.

Credentials harvested.

Lateral movement attempted via WMIC/PsExec.

Successful pivot via RDP.

Sensitive payroll file accessed and edited.

Data archived into Shares.7z.

Logs cleared to cover tracks.

🛠 Skills Demonstrated

Advanced KQL threat hunting

Process tree reconstruction

Reflective DLL detection

Cross-device correlation

Attack chain reconstruction

MITRE ATT&CK mapping

Defender onboarding gap analysis

🔒 Key Investigative Insight

The absence of file creation telemetry, combined with execution and network logs, revealed a critical gap:

The malicious file existed before Defender onboarding.

Recognizing telemetry gaps versus attacker tradecraft is a core detection engineering skill.

📌 Portfolio Purpose

This project demonstrates the ability to:

Follow an intrusion end-to-end

Pivot intelligently across telemetry tables

Validate assumptions with data

Identify stealth techniques

Reconstruct adversary behavior
