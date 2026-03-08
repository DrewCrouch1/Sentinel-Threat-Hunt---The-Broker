# Sentinel Threat Hunt – “The Broker”

Author: Andrew Crouch  
Platform: Microsoft Defender for Endpoint + Microsoft Sentinel  
Environment: Live Azure Lab Open To The Internet
Focus: Threat Hunting, Detection Engineering, Incident Reconstruction  

---

# Investigation Overview

This project documents a complete threat hunting investigation following the execution of a malicious executable disguised as a PDF:

```
daniel_richardson_cv.pdf.exe
```

The investigation reconstructs the attack chain from initial execution through attacker objectives using telemetry from Microsoft Defender for Endpoint and Microsoft Sentinel.

Observed attacker activity includes:

- Initial user execution via social engineering
- Command and control communication
- Credential harvesting using reflective loading
- Persistence mechanisms
- Lateral movement attempts
- Sensitive file access
- Data staging
- Anti-forensics activity

The investigation is documented exactly as it was performed — **pivot by pivot**.

---

# Initial Lead – User & Device Pivot

Starting Investigation Point

User: **Sophie.Turner**  
Device: **AS-PC1**

<img width="732" height="496" alt="image" src="https://github.com/user-attachments/assets/7a616bcd-66e8-40b7-8bea-fa2a99855279" />

### KQL Query

```
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where AccountName =~ "Sophie.Turner"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Result

The query revealed execution of the file:

```
daniel_richardson_cv.pdf.exe
```

The file was an **executable disguised as a PDF document**.

<img width="1413" height="373" alt="Screenshot 2026-02-23 205049" src="https://github.com/user-attachments/assets/decf47b6-5fdf-4bb8-acd0-cce2ace35996" />

---

# Was It User-Driven Execution?

### KQL Query

```
DeviceProcessEvents
| where InitiatingProcessSHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, InitiatingProcessParentFileName, InitiatingProcessIntegrityLevel
```

### Finding

Parent Process: **explorer.exe**  
Integrity Level: **High**

### Conclusion

The malicious file was executed through a **user double-click action**, confirming a likely **phishing or social engineering initial access vector**.

<img width="1410" height="394" alt="Screenshot 2026-02-23 221245" src="https://github.com/user-attachments/assets/6ee73dc6-ec66-41ee-b1b3-20df71e37ca1" />

---

# Post-Execution Enumeration

Immediately after execution, the payload initiated discovery commands:

```
whoami
hostname
net user
net localgroup administrators
net view
```

### Interpretation

This activity aligns with typical attacker discovery behavior used to enumerate:

- system identity
- local accounts
- administrative privileges
- accessible network resources

MITRE ATT&CK Techniques:

- **T1082 – System Information Discovery**
- **T1018 – Remote System Discovery**

<img width="1407" height="396" alt="Screenshot 2026-02-23 223450" src="https://github.com/user-attachments/assets/7d51840b-290f-4cfa-b694-7a004774cf78" />

---

# Command & Control Confirmation

### KQL Query

```
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| project Timestamp, RemoteIP, RemoteUrl
```

### Result

Outbound HTTPS communication observed to:

```
104.21.30.237
sync.cloud-endpoint.net
```

### Conclusion

The malware successfully established **command-and-control (C2) communication**.

<img width="944" height="185" alt="Screenshot 2026-02-26 211146" src="https://github.com/user-attachments/assets/e0f0d65a-5aec-42c0-973d-27fed116bd17" />

<img width="1469" height="69" alt="Screenshot 2026-02-24 222655" src="https://github.com/user-attachments/assets/d5ca3db7-56a2-44ea-9fa3-e6344b19a8db" />

---

# How Did the Executable Reach the System?

This question became a critical investigative pivot.

### KQL Query

```
DeviceFileEvents
| where FileName == "daniel_richardson_cv.pdf.exe"
```

### Finding

No **FileCreated** telemetry was found.

However:

- Process execution telemetry existed
- Network telemetry existed

### Conclusion

The malicious file was likely placed on disk **before Microsoft Defender onboarding**.

This conclusion was validated through:

- timeline correlation
- presence of execution telemetry without file creation telemetry

<img width="1428" height="221" alt="Screenshot 2026-02-24 224033" src="https://github.com/user-attachments/assets/41c3c268-a409-4075-9db5-05454aee6d4f" />

---

# Persistence Mechanisms

The attacker established persistence using multiple techniques.

### Remote Access Tool Deployment

`CertUtil` was used to install **AnyDesk.exe** across multiple systems:

- AS-PC1
- AS-PC2
- AS-SRV

AnyDesk is legitimate software but commonly abused by attackers for stealthy persistence.

Capabilities include:

- encrypted remote control
- file transfer
- GUI access

<img width="1410" height="218" alt="Screenshot 2026-02-23 224055" src="https://github.com/user-attachments/assets/796abbf5-c479-474e-92ed-a28518b632ea" />

### Scheduled Task Persistence

A scheduled task named:

```
MicrosoftEdgeUpdateCheck
```

was created to execute:

```
RuntimeBroker.exe
```

Daily at **3:00 AM** with **highest privileges**.

Hash analysis confirmed:

```
RuntimeBroker.exe == daniel_richardson_cv.pdf.exe
```

<img width="1469" height="69" alt="Screenshot 2026-02-24 222655" src="https://github.com/user-attachments/assets/00cbf497-0c46-4492-818d-445dcdfd7692" />

<img width="1428" height="221" alt="Screenshot 2026-02-24 224033" src="https://github.com/user-attachments/assets/dbe699a1-767f-4283-8a90-aae6a4721555" />

<img width="1475" height="73" alt="Screenshot 2026-02-24 220037" src="https://github.com/user-attachments/assets/30740e41-92b9-4ab5-b610-903b75b9a721" />

---

# Credential Theft Detection

### KQL Query

```
DeviceProcessEvents
| where FileName == "reg.exe"
| where ProcessCommandLine has_any ("save HKLM\\SYSTEM","save HKLM\\SAM")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### Finding

Registry hives were exported to:

```
C:\Users\Public
```

These files contain **password hashes** that can be cracked offline.

<img width="1355" height="122" alt="Screenshot 2026-02-23 225627" src="https://github.com/user-attachments/assets/ba9a58ba-eec4-488b-aaf0-6179f765ce23" />

---

### Reflective Credential Theft

### KQL Query

```
DeviceEvents
| where ActionType == "ClrUnbackedModuleLoaded"
| project Timestamp, InitiatingProcessFileName, AdditionalFields
```

### Finding

Module loaded:

```
SharpChrome
```

Process:

```
notepad.exe
```

### Interpretation

SharpChrome was injected **directly into memory**, indicating credential harvesting through reflective .NET assembly loading.

<img width="1372" height="68" alt="Screenshot 2026-02-24 210822" src="https://github.com/user-attachments/assets/815168eb-3008-419b-a642-66734895322a" />

<img width="1341" height="380" alt="Screenshot 2026-02-24 212418" src="https://github.com/user-attachments/assets/cb01240a-00b3-41c2-a811-46dd203adf61" />

<img width="1320" height="236" alt="Screenshot 2026-02-24 211929" src="https://github.com/user-attachments/assets/2cf8f44f-6819-4d3a-9359-c298df770c95" />

---

# Lateral Movement

Observed attacker techniques:

- WMIC remote execution
- PsExec usage
- RDP pivot via `mstsc.exe`

Additional activity included:

- creation of account **svc_backup**
- account added to **Administrators group**

Successful pivot occurred to:

```
AS-PC2
User: david.mitchell
```

Administrator password was also modified.

<img width="1345" height="274" alt="Screenshot 2026-02-23 225815" src="https://github.com/user-attachments/assets/cb247ca2-4e81-4073-834b-83cb1ec5cef2" />

<img width="1322" height="136" alt="Screenshot 2026-02-24 205653" src="https://github.com/user-attachments/assets/74b5c85e-6c64-47e2-a7ef-6eff569bc1a4" />

<img width="1120" height="60" alt="Screenshot 2026-02-24 205858" src="https://github.com/user-attachments/assets/f661aea5-dd31-471d-a4c2-09dc24394e8e" />

<img width="1292" height="211" alt="Screenshot 2026-02-24 210149" src="https://github.com/user-attachments/assets/5ed1a768-06f6-494b-9203-c8b2727922a1" />

<img width="1081" height="139" alt="Screenshot 2026-02-24 214820" src="https://github.com/user-attachments/assets/f6a005c8-0ccc-4647-841f-771e221f4052" />

---

# Sensitive Payroll File Access

Target file:

```
\\AS-SRV\Payroll\BACS_Payments_Dec2025.ods
```

### KQL Query

```
DeviceFileEvents
| where FileName contains "BACS_Payments_Dec2025"
```

### Critical Artifact

```
.~lock.BACS_Payments_Dec2025.ods#
```

### Interpretation

The LibreOffice lock file confirms the file was **opened for editing**, not simply viewed.

<img width="1208" height="104" alt="Screenshot 2026-02-24 215408" src="https://github.com/user-attachments/assets/8a7ed0f7-386c-425b-90ec-ede4394c05b4" />

<img width="1413" height="345" alt="Screenshot 2026-02-24 231308" src="https://github.com/user-attachments/assets/dddcc783-f019-4de4-a0d7-bf7336ef6112" />

---

# Data Staging

Archive created:

```
Shares.7z
```

Tool used:

```
7zG.exe
```

### Conclusion

Sensitive data was compressed prior to potential exfiltration.

<img width="1404" height="74" alt="Screenshot 2026-02-24 223140" src="https://github.com/user-attachments/assets/1e8a6004-f5ac-4ec1-b2f7-429c265c97a2" />

MITRE Technique:

**T1560 – Archive Collected Data**

---

# Anti-Forensics Activity

### KQL Query

```
DeviceEvents
| where ActionType contains "Cleared"
```

### Result

Event logs were cleared using:

```
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl Windows PowerShell
```

### Conclusion

Log clearing activity indicates **defense evasion and indicator removal**.

<img width="1255" height="247" alt="Screenshot 2026-02-24 210451" src="https://github.com/user-attachments/assets/9b3f6512-6540-43f9-98e4-5c9c1c27e455" />

---

# MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|------|------|------|
| Initial Access | T1566 – Phishing | User executed disguised PDF |
| Execution | T1059 – Command Interpreter | cmd.exe, certutil, PowerShell |
| Persistence | T1053.005 – Scheduled Task | RuntimeBroker.exe scheduling |
| Persistence | T1136 – Create Account | svc_backup account creation |
| Persistence | T1219 – Remote Access Software | AnyDesk install/use |
| Credential Access | T1003 – Credential Dumping | SAM/SYSTEM export |
| Credential Access | T1550.002 – Pass the Hash | Potential later use |
| Discovery | T1082 – System Info Discovery | whoami/hostname/net commands |
| Lateral Movement | T1021 – Remote Services | RDP via mstsc.exe |
| Collection | T1560 – Archive Collected Data | Shares.7z |
| Defense Evasion | T1070 – Indicator Removal | wevtutil log clearing |
| Command & Control | T1071 – HTTPS | Outbound C2 traffic |

---

# Full Attack Chain Summary

1. User executed disguised PDF malware.
2. Payload established HTTPS command-and-control.
3. System enumeration conducted.
4. Persistence mechanisms deployed.
5. SharpChrome credential harvesting executed in memory.
6. Credentials extracted via SAM/SYSTEM export.
7. Lateral movement attempted via WMIC/PsExec.
8. Successful pivot through RDP.
9. Sensitive payroll file accessed and modified.
10. Data staged into compressed archive.
11. Logs cleared to remove indicators.

---

# Skills Demonstrated

- Advanced KQL threat hunting
- Process tree reconstruction
- Reflective DLL detection
- Cross-device investigation
- Attack chain reconstruction
- MITRE ATT&CK mapping
- Defender telemetry gap analysis

---

# Key Investigative Insight

The absence of **file creation telemetry**, combined with existing execution and network logs, revealed a critical detection gap.

The malicious file existed **before Microsoft Defender onboarding**, explaining the missing file creation events.

Recognizing the difference between **telemetry gaps and attacker tradecraft** is a key detection engineering skill.

---

# Portfolio Purpose

This investigation demonstrates the ability to:

- Follow an intrusion end-to-end
- Pivot intelligently across telemetry tables
- Validate hypotheses with data
- Identify stealth techniques
- Reconstruct adversary behavior
