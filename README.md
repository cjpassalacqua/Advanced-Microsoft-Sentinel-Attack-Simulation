# Advanced-Microsoft-Sentinel-Attack-Simulation
Privilege Escalation • Persistence • Conditional Access Tampering • OAuth Backdoor (Full Kill Chain)

Below is a **professional, clean, GitHub-ready `README.md`** you can paste directly into your repo.
It’s formatted with headings, badges, code blocks, diagrams, and MITRE mapping — exactly like top-tier cybersecurity portfolios.

---

# Advanced Sentinel Attack Simulation

### **Privilege Escalation • OAuth Backdoor • Conditional Access Tampering • UEBA / Fusion Analysis**

---

## Overview

This project demonstrates a full **adversary attack simulation** performed inside a Microsoft Sentinel security lab.
The attack chain mirrors real-world cloud intrusions targeting Microsoft Entra ID (Azure AD), including:

* Privilege escalation
* Identity persistence
* OAuth backdoor creation
* Conditional Access policy tampering
* Suspicious sign-ins & token behavior
* Multi-location anomaly generation
* UEBA + Sentinel Fusion correlation

This simulation generated multiple **high-severity incidents**, detected through Microsoft Sentinel, User & Entity Behavior Analytics (UEBA), and Azure Activity Logs.

---

## Lab Environment

* **Microsoft Sentinel (SIEM)**
* **Log Analytics Workspace**
* **Microsoft Entra ID (Azure AD)**
* **UEBA + Identity Analytics**
* **Azure Activity Logs**
* **Audit Logs, Sign-In Logs, Security Events**
* **Custom Lab Users + RBAC Roles**
* **Azure Policy Compliance & Diagnostic Pipelines**

---

## Objectives

* Replicate a full attack chain used by modern threat actors.
* Test Sentinel analytics rules, UEBA, and Fusion detection.
* Produce real incidents for threat hunting using KQL.
* Document attack paths for blue team analysis.
* Create a portfolio-grade writeup demonstrating cloud security expertise.

---

# Attack Scenario: Full Kill Chain

## 1. Persistence: Creation of Attacker Account

A new identity is created to simulate an attacker foothold:

* **User:** attacker-admin
* **Role:** none initially

**Logs Generated:** AuditLogs, Directory Provisioning

---

## 2. Privilege Escalation: Global Administrator Assignment

The attacker escalates privileges by assigning **Global Administrator**:

**Detections Triggered:**

* Privileged Role Assignment
* High-Risk Role Escalation
* UEBA – Privilege Behavior Deviation

**MITRE Techniques:**

* T1068 (Privilege Escalation)
* T1078 (Valid Accounts)

---

## 3. OAuth Backdoor Creation

A malicious OAuth app is registered:

* **Name:** StealthApp-OAuth-Backdoor
* Client secret created
* Intended for persistence / token abuse

**Detections Triggered:**

* Suspicious App Registration
* High-Impact Secret Added

**MITRE Techniques:**

* T1528 (Steal App Access Token)
* T1556 (Modify Authentication Process)

---

## 4. Admin Consent + Privileged API Permissions

Attacker grants the backdoor app full directory control:

* **Microsoft Graph → Directory.ReadWrite.All
* **Admin Consent → Granted**

**Detections Triggered:**

* Privileged Consent Granted
* OAuth Abuse
* Directory Manipulation

**MITRE Techniques:**

* T1098 (Account Manipulation)
* T1114 (Email/Directory Collection)

---

## 5. Conditional Access Tampering

Attacker modifies CA policy to weaken authentication controls:

Actions:

* CA policy edited
* Exclusion added for attacker-admin
* Security enforcement disabled

**Detections Triggered:**

* Conditional Access Policy Modified
* Conditional Access Disabled
* MFA Exclusion Event

**MITRE Techniques:**

* T1556 (Authentication Process Modification)
* T1606 (Forge Web Credentials)

---

## 6. Suspicious Sign-Ins & Token Abuse

Attacker signs in from:

* Multiple browsers
* Private sessions
* Different geolocations (VPN)

**Detections Triggered:**

* Impossible Travel
* Risky Sign-In
* Unfamiliar Sign-In Properties
* Token Replay Behavior

**MITRE Techniques:**

* T1078 (Valid Account Abuse)
* T1609 (Cloud Service Enumeration)

---

# Resulting Sentinel Alerts & Incidents

### High Severity

* Global Administrator Assigned
* Admin Consent Granted to OAuth App
* Conditional Access Policy Modified
* OAuth App Granted Directory.ReadWrite.All

### Medium Severity

* Suspicious Application Registration
* Impossible Travel Detected
* Authentication Method Changed
* UEBA Sign-In Anomaly

### Low Severity

* New User Created
* Successful Sign-In from New Device

All incidents were correlated automatically using **Fusion** and **UEBA insights**, producing multi-stage attack graphs.

---

# KQL Queries Used for Investigation

### Sign-In Analysis

```kql
SigninLogs
| where UserPrincipalName contains "attacker-admin"
| sort by TimeGenerated desc
```

### Privileged Role Changes

```kql
AuditLogs
| where ActivityDisplayName startswith "Add member to role"
| sort by TimeGenerated desc
```

### OAuth App Activity

```kql
AuditLogs
| where ActivityDisplayName contains "application"
| sort by TimeGenerated desc
```

### Azure Activity Role Assignments

```kql
AzureActivity
| where Caller contains "attacker-admin"
| sort by TimeGenerated desc
```

### All Alerts Generated

```kql
AlertInfo
| sort by TimeGenerated desc
```

---

# Defensive Learnings

This simulation demonstrates:

* The importance of auditing role changes
* How attackers create invisible persistence
* Why OAuth app abuse is a major cloud threat
* How Conditional Access tampering can bypass MFA
* The value of UEBA in detecting subtle changes in behavior
* How Sentinel correlates multi-stage intrusions

---

# Cleanup (Post-Attack)

* Remove attacker-admin from privileged roles
* Delete OAuth backdoor app & client secrets
* Restore Conditional Access policy
* Clear unwanted admin consents
* Confirm no lingering RBAC assignments

---

# Conclusion

This attack simulation replicates the tactics of advanced cloud threat actors and validates Microsoft Sentinel’s ability to detect:

* Privilege escalation
* Persistence mechanisms
* OAuth backdoors
* Conditional Access manipulation
* Suspicious authentication patterns

It showcases practical skills in:

* Cloud security engineering
* SIEM configuration (Microsoft Sentinel)
* KQL threat hunting
* Identity protection
* Incident investigation
* MITRE ATT&CK threat mapping

---
