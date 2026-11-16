# Lab Environment

## Overview

This document describes the lab environment used throughout this repository.

The lab is designed to simulate attacks in a controlled environment, collect endpoint telemetry, generate security alerts, investigate incidents, and document the complete investigation process. Microsoft Sentinel serves as the central SIEM platform, with Wazuh providing additional endpoint monitoring and File Integrity Monitoring (FIM) capabilities.

Unless stated otherwise, every investigation in this repository uses this environment, with additional infrastructure introduced when required.

---

## Architecture

The environment consists of a Windows endpoint, a Kali Linux attacker, and an Ubuntu-based Wazuh Manager running as virtual machines. Windows telemetry is collected through Microsoft Azure Monitor Agent (AMA) and Wazuh Agent.

Microsoft Sentinel receives telemetry through two collection paths:

1. Windows Event Logs and Sysmon are collected through AMA and Data Collection Rules (DCR).
2. Wazuh alerts are forwarded through a custom Python shipper into a custom Log Analytics table.

Both telemetry paths converge in Microsoft Sentinel, where security events can be correlated and investigated using Kusto Query Language (KQL).

```text
                         Windows Endpoint
                                |
                 +--------------+--------------+
                 |                             |
                 v                             v
        Windows Event Logs + Sysmon       Wazuh Agent
                 |                             |
                 v                             v
        Azure Monitor Agent              Wazuh Manager
                 |                             |
                 v                             v
        Data Collection Rule             Wazuh FIM Alerts
                 |                             |
                 v                             v
        Log Analytics Workspace       Custom Python Shipper
                 |                             |
                 |                             v
                 |                    Log Analytics Workspace
                 |                             |
                 +--------------+--------------+
                                |
                                v
                       Microsoft Sentinel
                                |
                                v
                      Scheduled Analytics Rules
                                |
                                v
                         Alerts & Incidents
```

---

## Current Environment

- Windows Endpoint
- Kali Linux (Attacker VM)
- Ubuntu Linux (Wazuh Manager)
- Wazuh Agent and File Integrity Monitoring
- Microsoft Sentinel
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Log Analytics Workspace (LAW)

---

## Telemetry Flow

The laboratory uses two complementary telemetry collection paths.

### Microsoft Sentinel Telemetry

1. An attack is performed against the Windows endpoint.
2. Windows Event Logs and Sysmon record the activity.
3. Azure Monitor Agent collects the configured telemetry.
4. Data Collection Rules determine which events are forwarded.
5. Events are stored in Log Analytics Workspace.
6. Microsoft Sentinel analyzes the collected data.
7. Scheduled Analytics Rules generate alerts when detection conditions are met.
8. Alerts are investigated and documented.

### Wazuh Telemetry

1. Wazuh Agent monitors the configured Windows endpoint.
2. Wazuh collects endpoint security events and File Integrity Monitoring data.
3. Wazuh Manager processes the collected events and generates alerts.
4. A custom Python shipper forwards selected Wazuh alerts to Log Analytics Workspace.
5. Wazuh alerts are ingested into the custom `WazuhAlerts_CL` table.
6. Microsoft Sentinel can correlate Wazuh alerts with other collected telemetry.

---

## Network Layout

The attacker and victim machines communicate through the configured VirtualBox networking environment. The Windows endpoint and Wazuh Manager also communicate to support endpoint monitoring and telemetry collection.

The lab maintains the outbound connectivity required for communication with Microsoft Azure.

```text
                    VirtualBox Lab Network
                              |
             +----------------+----------------+
             |                |                |
             v                v                v
         Kali Linux     Windows Endpoint   Ubuntu Linux
          (Attacker)       (Victim)       (Wazuh Manager)
                                |
                  +-------------+-------------+
                  |                           |
                  v                           v
          Microsoft Azure                Wazuh Manager
                  |                           |
                  v                           v
         Log Analytics Workspace       Wazuh FIM Alerts
                  |
                  v
         Microsoft Sentinel
```

---

## Design Decisions

- Attack telemetry is generated through controlled simulations instead of public datasets.
- Every investigation follows a structured process involving attack simulation, telemetry collection, detection, and investigation.
- Multiple telemetry sources are used to improve endpoint visibility and support event correlation.
- Microsoft Sentinel serves as the central SIEM platform for analyzing collected security telemetry.
- Wazuh provides additional endpoint monitoring and File Integrity Monitoring capabilities.
- The environment is documented separately so investigation reports remain focused on analysis rather than infrastructure.
- The lab is intentionally expanded only when additional infrastructure is required for a specific investigation.

---

## Scope

This environment serves as the foundation for investigations covering:

- Endpoint Security
- Active Directory
- Microsoft Security
- Network Security
- Security Monitoring and Detection Engineering
- File Integrity Monitoring

---

## Investigation-Specific Infrastructure

The laboratory can be extended with additional infrastructure when required by a specific investigation.

For Investigation 002, an internal email environment was temporarily integrated into the lab to reproduce a realistic phishing scenario. This included Postfix, Dovecot, dnsmasq, email authentication records, TLS, and Thunderbird.

Investigation-specific infrastructure is documented within the corresponding investigation rather than being treated as part of the core laboratory architecture.

---

## Investigations Using This Environment

The environment currently supports the following investigations:

- [001 - Unauthorized Remote Authentication Attempt Against RDP Service](../01-Investigations/01-Windows-Endpoint/001-unauthorized-rdp-authentication-attempt/)
- [002 - Typosquatted Phishing Endpoint Compromise](../01-Investigations/01-Windows-Endpoint/002-typosquatted-phishing-endpoint-compromise/)
- [003 - LSASS Credential Dumping & LOLBin Tradecraft](../01-Investigations/01-Windows-Endpoint/003-lsass-credential-dumping-lolbin-tradecraft/)
- [004 - In-Memory PowerShell and WMI Event-Subscription Persistence](../01-Investigations/01-Windows-Endpoint/004-in-memory-powershell-wmi-persistence/)

Additional investigations will be added as the laboratory is expanded.

The lab evolves alongside the investigations. Its core architecture combines endpoint telemetry collection, Wazuh monitoring, and Microsoft Sentinel detection. Additional systems and services are introduced when they are required to support new investigation scenarios.
