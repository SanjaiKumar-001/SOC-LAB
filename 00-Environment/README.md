# Lab Environment

## Overview

This document describes the lab environment used throughout this repository.

The lab is designed to simulate attacks in a controlled environment, collect Windows telemetry, generate Microsoft Sentinel alerts, investigate incidents, and document the complete investigation process. Unless stated otherwise, every investigation in this repository is performed using this environment.

---

## Architecture

The current environment consists of a Windows endpoint and a Kali Linux attacker running as isolated virtual machines. Windows telemetry is collected and forwarded to Microsoft Sentinel, where detections are performed using Scheduled Analytics Rules and Kusto Query Language (KQL).

```text
Kali Linux
     ↓
Windows Endpoint
     ↓
Windows Event Logs + Sysmon
     ↓
Azure Monitor Agent (AMA)
     ↓
Data Collection Rule (DCR)
     ↓
Log Analytics Workspace (LAW)
     ↓
Microsoft Sentinel
     ↓
Scheduled Analytics Rules
     ↓
Alerts & Incidents
```

---

## Current Environment

- Windows Endpoint
- Kali Linux
- Microsoft Sentinel

---

## Telemetry Flow

The telemetry pipeline remains consistent throughout the project.

1. An attack is performed against the Windows endpoint.
2. Windows Event Logs and Sysmon record the activity.
3. Azure Monitor Agent collects the configured telemetry.
4. Data Collection Rules determine which events are forwarded.
5. Events are stored in Log Analytics Workspace.
6. Microsoft Sentinel analyzes the collected data.
7. Scheduled Analytics Rules generate alerts when detection conditions are met.
8. Alerts are investigated and documented.

---

## Network Layout

The attacker and victim machines communicate through an isolated VirtualBox NAT network while maintaining outbound connectivity required for Azure.

```text
                 VirtualBox NAT Network
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
  Kali Linux                    Windows Endpoint
                                        │
                                        ▼
                                Microsoft Azure
                                        │
                                        ▼
                               Microsoft Sentinel
```

---

## Design Decisions

- Attack telemetry is generated through controlled simulations instead of public datasets.
- Every alert can be traced back to a known attack performed within the lab.
- The environment is documented separately so investigation reports remain focused on analysis rather than infrastructure.
- The lab is intentionally expanded only when additional infrastructure is required for a specific investigation.

---

## Scope

This environment serves as the foundation for investigations covering:

- Endpoint Security
- Active Directory
- Microsoft Security
- Network Security
- Attack Chain Analysis
- Independent Detection Engineering Scenarios

The lab evolves alongside the investigations. The initial environment focuses on endpoint telemetry and Microsoft Sentinel, with additional systems and services introduced only when they are required to support future investigation scenarios.
