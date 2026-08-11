# Investigation 002

# Phishing & Endpoint Compromise

| **Field**        | **Value**                      |
| ---------------- | ------------------------------ |
| Investigation ID | 002                            |
| Phase            | Phase 01 – Endpoint Security   |
| Category         | Phishing & Endpoint Compromise |
| Platform         | Microsoft Sentinel             |
| Status           | Completed                      |

---

# Incident Overview

On **8 August 2026**, an employee named **Victor** reported receiving an email that appeared to originate from the organization's payroll department.

The message was sent from:

```text
payroll@skynett.com
```

while the legitimate organizational domain was:

```text
skynet.com
```

The one-character difference represented a **typosquatting** attempt.

The email used the subject:

```text
Salary Revision & Increment Letter - FY2026
```

The attachment was named:

```text
Salary_Revision_2026.xls.bat
```

In Thunderbird, the complete filename, including the `.bat` extension, was visible in the attachment area.

![Figure 1 - Phishing Email Received in Thunderbird](screenshots/01_phishing_email_thunderbird.png)

**Figure 1 – Phishing Email Received in Thunderbird**

Victor did not notice the `.bat` extension clearly. When he attempted to preview the attachment, the preview did not load.

However, because the email appeared to contain a **salary revision and increment letter**, Victor did not think twice about proceeding with the attachment. He downloaded and opened the file.

When the attachment was saved through Windows File Explorer, the filename appeared as:

```text
Salary_Revision_2026.xls
```

without the `.bat` portion being visibly presented in that particular save interface.

![Figure 2 - Attachment Save View in Windows File Explorer](screenshots/02_attachment_save_filename.png)

**Figure 2 – Attachment Save View in Windows File Explorer**

After the file was opened, a command prompt window briefly appeared and closed.

Victor subsequently reported the suspicious activity, and the event was escalated to the SOC for investigation.

---

# Objective

The objectives of the investigation were to:

1. Determine how the suspicious attachment reached the endpoint and whether Victor's account of the event was supported by telemetry.
2. Identify the execution chain and determine what actions were performed by the suspicious file.
3. Identify any persistence mechanisms and network activity associated with the execution.
4. Validate the discovered artifacts directly on the affected endpoint.
5. Contain the simulated compromise and develop a behavioral Microsoft Sentinel detection capable of identifying similar attack patterns.

---

# Lab Environment

| **Component**       | **Details**                 |
| ------------------- | --------------------------- |
| Attacker            | Kali Linux – BUGGY-ATK01    |
| Victim              | Windows 11 – ZORO-WS01      |
| Victim User         | Victor                      |
| SIEM                | Microsoft Sentinel          |
| Endpoint Telemetry  | Sysmon                      |
| Email Client        | Mozilla Thunderbird         |
| Mail Infrastructure | Postfix + Dovecot + dnsmasq |
| Internal Network    | VirtualBox NAT Network      |
| Attacker IP         | 10.0.10.4                   |

The investigation was performed within a controlled SOC laboratory environment.

---

# Email Infrastructure & Phishing Simulation

## 5.1 Purpose

A complete internal email environment was constructed on **BUGGY-ATK01** to reproduce the phishing scenario within the SOC laboratory.

The environment consisted of:

```text
                         BUGGY-ATK01
                         Kali Linux
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
       Postfix              Dovecot            dnsmasq
        SMTP                 IMAP             Internal DNS
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
                              ▼
                       ZORO-WS01
                       Windows 11
                              │
                         Thunderbird
                              │
                           Victor
```

The goal was to create an end-to-end mail workflow where the attacker could send a message, the victim could receive it through a normal desktop mail client, and the SOC could investigate the resulting endpoint activity.

---

## 5.2 Postfix

**Postfix** was deployed on BUGGY-ATK01 to provide SMTP functionality for the laboratory mail environment.

It handled the transmission and delivery of messages between the simulated domains:

```text
skynett.com
```

and:

```text
skynet.com
```

The mail environment was tested until messages could successfully move through the complete SMTP workflow and arrive in the victim mailbox.

---

## 5.3 Dovecot

**Dovecot** provided IMAP access to the mailboxes.

This allowed Thunderbird on ZORO-WS01 to retrieve messages from the mail server.

The resulting workflow was:

```text
Postfix
   ↓
Mailbox
   ↓
Dovecot / IMAP
   ↓
Thunderbird
   ↓
Victor
```

This allowed the phishing scenario to be experienced from the same type of graphical mail-client workflow normally used by an end user.

---

## 5.4 dnsmasq

**dnsmasq** provided DNS functionality for the laboratory mail environment.

It resolved the internal mail hosts while also forwarding external DNS requests when required.

The simulated mail domains included:

```text
skynet.com
skynett.com
```

with the mail infrastructure resolving internally to:

```text
mail.skynett.com → 10.0.10.4
mail.skynet.com  → 10.0.10.4
```

The environment also included MX, SPF, DKIM and DMARC records for the simulated domains.

---

## 5.5 Email Authentication Records

SPF, DKIM and DMARC records were configured for the simulated domains.

These were included to make the laboratory mail environment behave as realistically as possible and to provide practical experience with the relationship between:

```text
DNS
 ↓
Mail routing
 ↓
Email authentication
 ↓
Mail delivery
```

The objective was to build the environment as close to a genuine organizational mail workflow as reasonably possible so that the laboratory provided practical experience rather than a simplified demonstration.

---

## 5.6 TLS and Certificate Configuration

TLS certificates were configured for the mail services as part of the effort to make the laboratory environment behave as realistically as possible.

Because the mail environment was internally controlled, self-signed certificates were used for the laboratory mail services.

---

## 5.7 Thunderbird and SMTP Validation

Mozilla Thunderbird was used as the end-user mail client on ZORO-WS01.

The mailboxes were tested using the same graphical workflow an employee would normally use.

**Swaks** was used during the earlier infrastructure-building stage to interact with the SMTP service and observe how the SMTP protocol operates, including the initial `EHLO` exchange and message handoff.

The final phishing scenario was performed through Thunderbird to reproduce a normal GUI-based employee mail workflow.

Troubleshooting the mail infrastructure during construction also provided practical experience with the interaction between **DNS, SMTP, IMAP and TLS**.

---

# Initial Investigation

The SOC analyst began by reviewing Sysmon process creation events from the affected endpoint to identify suspicious activity around the reported time.

The following KQL query was used:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where TimeGenerated > ago(12h)
| extend IST = datetime_utc_to_local(TimeGenerated, "Asia/Kolkata")
| project IST, Computer, EventData
| order by IST desc
```

![Figure 3 - Initial Sysmon Process Activity](screenshots/03_initial_sysmon_process_activity.png)

**Figure 3 – Initial Sysmon Process Activity**

After reviewing the results, the analyst observed a cluster of suspicious process executions, including:

* `ipconfig.exe`
* `systeminfo.exe`
* `netstat.exe`
* `tasklist.exe`
* `reg.exe`
* `schtasks.exe`
* `powershell.exe`

These processes appeared within a short period and warranted further investigation.

---

# Artifact Pivot & Suspicious Process Execution

While examining the Event ID 1 events, the analyst identified a parent command line referencing:

```text
Salary_Revision_2026.xls.bat
```

This shifted the investigation toward the identified file as the primary artifact.

The following query was used to search for events associated with the filename:

```kql
Event
| where TimeGenerated > ago(24h)
| where EventData contains "Salary_Revision_2026.xls.bat"
| extend IST = datetime_utc_to_local(TimeGenerated, "Asia/Kolkata")
| serialize
| extend S_NO = row_number()
| project S_NO, IST, Source, EventID, RenderedDescription, EventData
| order by IST asc
```

The search returned multiple Sysmon events, including:

* **Event ID 11** – File Creation
* **Event ID 15** – File Stream Creation
* **Event ID 1** – Process Creation

Examining the EventData from the process-creation events revealed:

```xml
<Data Name="ParentCommandLine">cmd /c "C:\Users\Victor\Desktop\Salary_Revision_2026.xls.bat" min</Data>
```

This confirmed that the suspicious activity originated from the batch file located on Victor's Desktop.

---

# File Stream Analysis

The analyst reviewed the Event ID 15 events associated with the identified artifact.

The following query was used:

```kql
Event
| where TimeGenerated > ago(24h)
| where EventData contains "Salary_Revision_2026.xls.bat"
| where EventID == 15
| extend IST = datetime_utc_to_local(TimeGenerated, "Asia/Kolkata")
| project IST, Source, EventID, RenderedDescription, EventData
| order by IST asc
```

One of the events contained information associated with the file's `Zone.Identifier` alternate data stream.

The relevant information was:

```text
[ZoneTransfer]
ZoneId=3
HostUrl=about:internet
```

![Figure 4 - Zone.Identifier Evidence](screenshots/04_zone_identifier.png)

**Figure 4 – Zone.Identifier Evidence**

`ZoneId=3` indicates that Windows associated the file with the Internet security zone.

This provided additional evidence supporting Victor's account that the suspicious file had been downloaded rather than created locally.

---

# Payload Recovery

The Event ID 15 data also exposed the contents of the recovered batch file.

![Figure 5 - Recovered Batch File Content](screenshots/05_recovered_batch_content.png)

**Figure 5 – Recovered Batch File Content**

The recovered payload contained commands performing system discovery, persistence attempts and a network connectivity test.

The relevant behavior was:

| **Action**                 | **Observed Behavior**                                                 |
| -------------------------- | --------------------------------------------------------------------- |
| System Information         | Executed `systeminfo`                                                 |
| Network Configuration      | Executed `ipconfig /all`                                              |
| Network Connections        | Executed `netstat -ano`                                               |
| Process Discovery          | Executed `tasklist /v`                                                |
| Scheduled Task Persistence | Attempted to create `WindowsSystemBackup`                             |
| Registry Persistence       | Attempted to create `SystemHelper` under the current user's `Run` key |
| Network Test               | Executed PowerShell `Test-NetConnection` toward `10.0.10.4:4444`      |

The recovered batch script was a non-evasive educational artifact generated within the controlled laboratory environment.

---

# Discovery Analysis

The payload performed several discovery actions before attempting persistence.

The commands recovered from the payload included:

```text
systeminfo
ipconfig /all
netstat -ano
tasklist /v
```

These commands collected information about:

* Operating system and system configuration
* Network interfaces and configuration
* Existing network connections
* Running processes

The activity demonstrated that the payload was not limited to simply executing the attached file. It attempted to gather information about the endpoint and its surrounding environment.

---

# Persistence Analysis

The recovered payload contained two persistence mechanisms.

## Registry Run Key

The payload attempted to create a Registry Run key under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The value created was:

```text
SystemHelper
```

This mechanism was successful under the Victor user context.

This represents:

**T1547.001 – Registry Run Keys / Startup Folder**

## Scheduled Task

The payload also attempted to create:

```text
WindowsSystemBackup
```

through `schtasks`.

However, this particular execution occurred under the **Victor standard-user account**.

The scheduled-task creation attempt failed because Victor did not have the required privileges.

The task was later checked during endpoint validation and cleanup. The verification did not show a task created by the final phishing execution, supporting the conclusion that this persistence attempt had failed.

---

# Endpoint Validation

The analyst subsequently validated the artifacts directly on ZORO-WS01.

The payload-created directory was:

```text
C:\Users\Victor\AppData\Local\Temp\SystemCache
```

The directory contained:

```text
logon_info.txt
netstat_connections.txt
network_config.txt
process_list.txt
sysinfo.txt
```

![Figure 6 - Payload Generated Files](screenshots/06_payload_generated_files.png)

**Figure 6 – Payload Generated Files**

The presence of these files correlated with the discovery commands recovered from the payload.

This provided independent endpoint validation that the discovery activity described by the recovered script had produced the expected artifacts.

The scheduled task was also checked using:

```powershell
schtasks /query /tn "WindowsSystemBackup"
```

The final phishing execution had been performed under Victor's standard-user context, and the scheduled-task creation attempt had failed.

---

# Network Activity Analysis

Based on the recovered payload, the analyst searched for activity associated with the attacker system.

The following query was used:

```kql
Event
| where TimeGenerated > ago(24h)
| where EventData contains "10.0.10.4"
| extend IST = datetime_utc_to_local(TimeGenerated, "Asia/Kolkata")
| project IST, Source, EventID, RenderedDescription, EventData
| order by IST asc
```

The investigation identified the PowerShell command:

```text
powershell -c "Test-NetConnection 10.0.10.4 -Port 4444"
```

The command was executed from the recovered batch file.

However, no corresponding Sysmon **Event ID 3** was observed to independently confirm a network connection.

Therefore, the evidence supports an **attempted network connectivity test**, but does not confirm successful callback communication or data transfer.

This distinction was preserved throughout the investigation.

---

# Attack Reconstruction

After completing the investigation, the collected evidence was correlated with the controlled attack simulation performed within the SOC laboratory.

The reconstructed attack chain was:

```text
Payroll Email
    ↓
Typosquatted sender domain: skynett.com
    ↓
Salary_Revision_2026.xls.bat
    ↓
Victor downloads and opens attachment
    ↓
cmd.exe executes batch payload
    ↓
Discovery Commands
    ├── systeminfo
    ├── ipconfig /all
    ├── netstat -ano
    └── tasklist /v
    ↓
Persistence Attempts
    ├── Scheduled Task → Failed
    └── Registry Run Key → Successful
    ↓
PowerShell Test-NetConnection
    ↓
Attempted Network Connectivity
```

---

# Attack Timeline

The investigation established the following sequence around the execution of the phishing payload:

| **Time (IST)** | **Activity**                                                                   |
| -------------- | ------------------------------------------------------------------------------ |
| 22:51:58       | `Zone.Identifier` information associated with the downloaded artifact observed |
| 22:52:09       | Batch payload execution begins                                                 |
| 22:52:10       | Discovery commands begin executing                                             |
| 22:52:14       | Additional discovery and persistence-related commands execute                  |
| 22:52:20       | Registry persistence and subsequent commands execute                           |
| 22:52:30       | Network connectivity test activity observed                                    |

The timeline represents the narrative sequence of the attack. The detection output later in the investigation reflects raw telemetry event volume, where multiple Sysmon events can correspond to a single payload execution.

---

# Containment Actions

Following confirmation that the endpoint had executed the suspicious payload, the SOC analyst performed containment and cleanup within the laboratory environment.

The malicious batch file was removed from the endpoint.

The payload-created artifacts under:

```text
C:\Users\Victor\AppData\Local\Temp\SystemCache
```

were also removed.

The Registry Run-key persistence created by the payload was removed.

The scheduled task was checked and cleanup was attempted. The resulting verification supported the conclusion that the scheduled-task persistence attempt from the final phishing execution had not succeeded.

The identified attacker IP address:

```text
10.0.10.4
```

was also identified for network-level blocking.

In a production environment, the source would be blocked at the organization's perimeter or relevant network security control.

---

# Detection Engineering

After containment, the analyst developed a Microsoft Sentinel Scheduled Analytics Rule designed to detect the behavioral sequence observed during the investigation.

The detection focuses on:

```text
Internet-originated file
        ↓
Batch execution through cmd.exe
        ↓
Registry Run-key persistence
        ↓
Shell-associated network activity
```

The rule does not depend on the specific filename, individual discovery command or attacker IP address used during this investigation.

## Detection Logic

The final detection query was:

```kql
Event
| where
    EventData contains "ZoneId=3"
    or (Source == "Microsoft-Windows-Sysmon" and EventID == 1 and EventData contains "cmd.exe" and EventData contains ".bat")
    or (Source == "Microsoft-Windows-Sysmon" and EventID == 13 and EventData contains "CurrentVersion\\Run")
    or (Source == "Microsoft-Windows-Sysmon" and EventID == 3 and (EventData contains "cmd.exe" or EventData contains "powershell.exe"))
| extend
    Download = iff(EventData contains "ZoneId=3", 1, 0),
    Execution = iff(Source == "Microsoft-Windows-Sysmon" and EventID == 1 and EventData contains "cmd.exe" and EventData contains ".bat", 1, 0),
    Persistence = iff(Source == "Microsoft-Windows-Sysmon" and EventID == 13 and EventData contains "CurrentVersion\\Run", 1, 0),
    Callback = iff(Source == "Microsoft-Windows-Sysmon" and EventID == 3 and (EventData contains "cmd.exe" or EventData contains "powershell.exe"), 1, 0)
| summarize
    DownloadEvents = sum(Download),
    ExecutionEvents = sum(Execution),
    PersistenceEvents = sum(Persistence),
    CallbackEvents = sum(Callback),
    FirstDownload = minif(TimeGenerated, Download == 1),
    FirstExecution = minif(TimeGenerated, Execution == 1),
    FirstPersistence = minif(TimeGenerated, Persistence == 1),
    FirstCallback = minif(TimeGenerated, Callback == 1)
    by Computer, bin(TimeGenerated, 5m)
| where DownloadEvents > 0 and ExecutionEvents > 0 and PersistenceEvents > 0
| where FirstDownload < FirstExecution and FirstExecution < FirstPersistence
| extend Confidence = case(
    CallbackEvents > 0 and FirstPersistence < FirstCallback, "High - Full Chain Confirmed",
    CallbackEvents > 0, "Medium - Callback Observed, Sequence Unconfirmed",
    "Medium - No Callback Telemetry Observed"
)
| extend
    Download_IST = datetime_utc_to_local(FirstDownload, "Asia/Kolkata"),
    Execution_IST = datetime_utc_to_local(FirstExecution, "Asia/Kolkata"),
    Persistence_IST = datetime_utc_to_local(FirstPersistence, "Asia/Kolkata"),
    Callback_IST = iff(CallbackEvents > 0, datetime_utc_to_local(FirstCallback, "Asia/Kolkata"), datetime(null))
| project
    Computer,
    Confidence,
    DownloadEvents,
    ExecutionEvents,
    PersistenceEvents,
    CallbackEvents,
    Download_IST,
    Execution_IST,
    Persistence_IST,
    Callback_IST
| order by Download_IST asc
```

The query intentionally evaluates the **behavioral sequence** rather than matching only the exact indicators used during this attack.

The sequence must occur in the following order:

```text
FirstDownload < FirstExecution < FirstPersistence
```

Network activity is treated as an additional confidence signal rather than a mandatory requirement for the core detection.

![Figure 7 - Detection Logic and Result](screenshots/07_detection_logic.png)

**Figure 7 – Detection Logic and Detection Result**

The detection rule was deployed as a **Microsoft Sentinel Scheduled Analytics Rule**.

The rule was configured to detect the behavioral sequence and generate an alert when the required conditions were met.

![Figure 8 - Detection Rule Deployment](screenshots/08_detection_rule_deployment.png)

**Figure 8 – Scheduled Analytics Rule Deployment**

---

# Detection Event Count Consideration

The detection rule can produce multiple execution events for a single payload execution because the broad `cmd.exe` + `.bat` condition can match several process-creation events generated during the execution chain.

Therefore, the event count represents **raw telemetry volume**, not the number of times the payload itself was executed.

The timeline presents the narrative sequence of the attack, while the detection output reflects the underlying event volume. The two representations serve different purposes.

---

# Detection Gap & Recommendation

The current detection focuses on shell-associated network activity through `cmd.exe` and `powershell.exe`.

This provides useful behavioral coverage without hard-coding the specific attacker IP address used in the laboratory scenario.

However, an attacker could potentially use another process to initiate network communication rather than directly relying on `cmd.exe` or `powershell.exe`.

Future detection engineering can therefore expand network-behavior coverage through broader process-lineage analysis and additional endpoint or network telemetry.

This represents a natural area for improving the detection in future investigations.

---

# Findings

The investigation confirmed that:

* Victor received a phishing email from the typosquatted domain **`skynett.com`**.
* The attachment was **`Salary_Revision_2026.xls.bat`**.
* The attachment was downloaded from the Internet, supported by **`ZoneId=3`**.
* Victor opened the attachment and the batch payload executed through **`cmd.exe`**.
* The payload performed system, network and process discovery.
* Registry Run-key persistence through **`SystemHelper`** was successfully created.
* Scheduled-task persistence through **`WindowsSystemBackup`** failed under the Victor standard-user context.
* The payload executed a PowerShell `Test-NetConnection` command toward **10.0.10.4:4444**.
* The network command demonstrated an **attempted connectivity test**, but successful callback communication was not confirmed through Sysmon Event ID 3.
* The payload-created discovery artifacts were independently validated on ZORO-WS01.
* Microsoft Sentinel successfully correlated the behavioral sequence.
* A Scheduled Analytics Rule was deployed to detect similar activity in the future.

---

# MITRE ATT&CK Mapping

| **Technique** | **Name**                                                 | **Evidence**                                              |
| ------------- | -------------------------------------------------------- | --------------------------------------------------------- |
| T1566.001     | Phishing: Spearphishing Attachment                       | Malicious attachment delivered through the phishing email |
| T1204.002     | User Execution: Malicious File                           | Victor downloaded and opened the malicious attachment     |
| T1059.003     | Command and Scripting Interpreter: Windows Command Shell | Batch payload executed through `cmd.exe`                  |
| T1059.001     | Command and Scripting Interpreter: PowerShell            | PowerShell used to execute `Test-NetConnection`           |
| T1082         | System Information Discovery                             | `systeminfo`                                              |
| T1016         | System Network Configuration Discovery                   | `ipconfig /all`                                           |
| T1049         | System Network Connections Discovery                     | `netstat -ano`                                            |
| T1057         | Process Discovery                                        | `tasklist /v`                                             |
| T1547.001     | Registry Run Keys / Startup Folder                       | `SystemHelper` created under the user's `Run` key         |
| T1053.005     | Scheduled Task/Job: Scheduled Task                       | `WindowsSystemBackup` creation was attempted but failed   |

---

# Key Investigation Takeaways

* **User behavior is an important part of the attack chain.** Victor's excitement about receiving a salary revision and increment letter contributed to the attachment being opened even though the preview failed. Technical controls alone are insufficient when users are persuaded to bypass or ignore warning signs.

* **Typosquatting remains an effective social-engineering technique.** The difference between `skynet.com` and `skynett.com` was small enough to appear legitimate to an unsuspecting employee.

* **The full filename matters.** The Thunderbird attachment displayed the complete `.xls.bat` filename, but Victor did not notice the extension clearly before opening it.

* **Endpoint telemetry should be investigated as a sequence rather than as isolated events.** The individual process executions became meaningful when correlated with the downloaded artifact and persistence activity.

* **Artifact pivoting is an effective investigation technique.** Once the suspicious filename was identified, searching for the same artifact across Sysmon events revealed its creation, file-stream information and execution.

* **`Zone.Identifier` provided valuable evidence.** `ZoneId=3` supported the conclusion that the file originated from the Internet.

* **Standard-user privileges can affect persistence.** The scheduled-task persistence attempt failed, while the HKCU Registry Run-key persistence succeeded because it operated within the user's own context.

* **Attempted activity should not automatically be treated as successful activity.** The `Test-NetConnection` command demonstrated an attempted network connection, but the absence of corresponding Sysmon Event ID 3 telemetry meant successful callback communication could not be confirmed.

* **Detection logic should focus on methodology rather than individual IOCs.** The final rule avoids depending on the specific malicious filename or attacker IP address and instead looks for the behavioral sequence of Internet-originated file activity, suspicious execution, persistence and shell-associated network activity.

* **Detection engineering should follow investigation.** The investigation first established what happened and then used those findings to develop a behavioral detection for similar future activity.

---

# Conclusion

Investigation 002 demonstrated a complete phishing-to-endpoint-compromise scenario within the SOC laboratory.

The investigation began with a realistic phishing email and progressed through user interaction, endpoint execution, Sysmon telemetry analysis, artifact identification, file and stream analysis, payload recovery, discovery analysis, persistence analysis, endpoint validation, containment and detection engineering.

The investigation workflow was:

```text
Phishing Email
      ↓
Endpoint Execution
      ↓
Process Investigation
      ↓
Artifact Identification
      ↓
File & Stream Analysis
      ↓
Payload Recovery
      ↓
Discovery Analysis
      ↓
Network Activity Analysis
      ↓
Persistence Analysis
      ↓
Endpoint Validation
      ↓
Containment
      ↓
Detection Engineering
      ↓
MITRE ATT&CK Mapping
```

The investigation also demonstrated the importance of building realistic supporting infrastructure rather than treating the attack as an isolated command execution.

The internal mail environment required practical work with **Postfix, Dovecot, dnsmasq, DNS, SMTP, IMAP, TLS, SPF, DKIM and DMARC**, while Thunderbird was used to reproduce the normal employee-facing email workflow. Troubleshooting these components during construction provided additional practical understanding of how email infrastructure and endpoint activity interact during a phishing incident.

Most importantly, the investigation demonstrated an evidence-driven SOC workflow: the initial user report was converted into a timeline, the suspicious artifact was identified and pivoted on, endpoint telemetry was correlated, the recovered payload was validated against endpoint artifacts, attempted activity was distinguished from confirmed activity, containment was performed, and the resulting attack methodology was converted into a reusable Microsoft Sentinel detection.

The final detection therefore moves beyond the specific indicators used in this laboratory scenario and provides a foundation for identifying similar phishing-driven endpoint compromise activity in future investigations.

