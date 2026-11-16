# SOC-LAB

This repository documents a hands-on SOC lab built through attack simulations, security monitoring, detection engineering, and incident investigations across multiple platforms and environments.

Each investigation follows a structured workflow from attack simulation to telemetry collection, detection, alert generation, investigation, and documentation, supported by technical evidence and SIEM queries.

## Project Goal

Build and document practical SOC investigations covering Windows and Linux endpoint security, SIEM platforms, Active Directory, network security, attack chains, threat detection, and independent security scenarios. Develop hands-on experience with security monitoring, threat hunting, incident investigation, and detection engineering using platforms such as Microsoft Sentinel and Splunk.

## Lab

The complete lab architecture, environment configuration, and data collection setup are documented in the [00-Environment](00-Environment/README.md) directory.

## Available Investigations

- [001 - Unauthorized Remote Authentication Attempt Against RDP Service](01-Investigations/01-Windows-Endpoint/001-unauthorized-rdp-authentication-attempt/)
- [002 - Typosquatted Phishing Endpoint Compromise](01-Investigations/01-Windows-Endpoint/002-typosquatted-phishing-endpoint-compromise/)
- [003 - LSASS Credential Dumping & LOLBin Tradecraft](01-Investigations/01-Windows-Endpoint/003-lsass-credential-dumping-lolbin-tradecraft/)
- [004 - In-Memory PowerShell and WMI Event-Subscription Persistence](01-Investigations/01-Windows-Endpoint/004-in-memory-powershell-wmi-persistence/)

This repository is continuously updated as new investigations are completed.
