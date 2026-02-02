---
title: "Understanding Identity Abuse in Entra ID through a Case Study (Xintra)"
layout: post-with-toc
background: '/img/huskycorp/oauthflow.png'
subtitle: "Exploring the ramifications of Identity Abuse in a simulated lab."
image: '/img/huskycorp/oauthflow.png'
tags: [research, cloud, containers, security]
categories: [research]
---

## Introduction
This is my write-up of an investigation I conducted while working through Xintra’s HuskyCorp incident simulation lab, along with what I learned throughout the process. The investigation revealed a hybrid end-to-end compromise and showed how an attacker can abuse identity in Entra ID in a variety of ways in order to escalate their privileges, maintain persistence, and effectively take over a tenant. By the end of the incident, the attacker gained administrative privileges within Entra, the on-premises Active Directory domain, and sensitive company information.

## Executive Summary
In late April 2024, Husky Corp triggered an incident response investigation after discovering suspicpious user activity within their Azure tenant. The investigation revealed that a threat actor was able to to gain control over several identities, applications, and workstations. The threat actor was also able to successfully access sensitive business information.

Based on the tactics, techniques, and procedures observed, the activity aligns closely with publicly reported Midnight Blizzard (APT 29) tradecraft. These operations are commonly associated with intelligence collection and long-term access rather than disruptive activity.

This case study analyzes how a threat actor like Midnight Blizzard leverages identity mechanisms within Entra ID to maintain persistence and escalate their privileges.

## Environment & Scope
Husky Corp's environment consists of an Azure tenant integrated with Entra ID with various Azure resources and an on-premises Active Directory forest.

![image1](/img/huskycorp/network-diagram.png)

Responders were provided with access to an ELK instance with pre-parsed logs, exported email artifacts, parsed browser outputs, and parsed KAPE outputs. 

The scope of this investigation was limited to artifacts provided within the simulation, including Entra ID sign-in and audit logs, Azure Activity Logs, Microsoft Graph telemetry, Windows host event logs, and parsed forensic outputs. Live containment actions and external infrastructure attribution were outside the scope of this analysis.

## Attack Overview
The following timeline reconstructs the attacker’s activity. Events are presented in chronological order to illustrate how the intrusion progressed from initial access to full hybrid compromise. 

![alt](/img/huskycorp/timeline.png)
## Attack Analysis
The following section provides an analysis of the different phases the threat actor executed, and the ramifications of such activities.

### Initial Detection
The incident began on April 20th, 2024  with multiple failed login attempts for the users `Ashlee@huskycorp.net`, `Lonnard@huskycorp.net`, and `lina@huskycorporation.onmicrosoft.com` all from the IP: `103.216.220.45`. The failures were recorded with the error `InvalidUserNameOrPassword`, indicating an attempt at password spraying. Tools such as [MSOLSpray](https://github.com/dafthack/MSOLSpray) are typically used to password spray Entra ID. The result of using such a tool is the influx of failed login attempts seen in the audit logs. This tool in particular takes note of the error codes returned from a failed login attempt, meaning that in instances where the credentials are correct but some other factor is blocking a successful login, the threat actor can use that information to adapt their approach.

![image2](/img/huskycorp/password-spraying.png)

This activity warranted further investigation into whether any credentials had been successfully validated.

### Identity Compromise
#### Credential Validation
Analysis of Entra ID sign-in logs show that the attacker was able to successfuly validate the credentials for two users: `Lonnard@huskycorp.net` and `Ashlee@huskycorp.net`. Both Ashlee and Lonnard were using Pass-Through-Authentication, meaning that these users’ passwords are validated through an on-premises agent rather than authenticated through the cloud.

![image3](/img/huskycorp/conditionalaccesspta.png)

##### Conditional Access Behavior
Although the attacker was able to obtain the credentials for Lonnard's and Ashlee's accounts, the login attempt is blocked by the Conditional Access policies.

![image4](/img/huskycorp/conditionaccessfailure.png)

However, Conditional Access controls did not fully stop the threat actor. Subsequent successful sign-ins for `Lonnard@huskycorp.net` were observed originating from a different IP address (`146.70.196.180`), suggesting the attacker adapted infrastructure to bypass Conditional Access policies.

![image5](/img/huskycorp/lonnardsignin.png)

#### Token-Based Access and Tenant Enumeration
Following successful authentication as `Lonnard@huskycorp.net`, sign-in activity was observed with the user agent `azurehound/v2.1.8`. [AzureHound](https://unit42.paloaltonetworks.com/threat-actor-misuse-of-azurehound/) is a Microsoft Graph enumeration tool commonly used to map identity relationships, role assignments, and application permissions within Entra ID. Audit logs confirmed that shortly after this authentication event, the attacker initiated multiple Microsoft Graph API requests targeting directory objects, applications, and role assignments.

![image6](/img/huskycorp/graphapirecon.png)

### Persistence Mechanisms and Data Exfiltration
After the attacker's initial reconnaissance, they focused on establishing persistence within Entra ID using cloud-native mechanisms. These techniques allowed the threat actor to maintain access without solely relying on credentials while also reducing the effectiveness of remediation actions like password resets or MFA enforcement.


#### OAuth Abuse
An OAuth application in Azure authorizes software to access resources on behalf of a user without the need for a password. Attackers commonly use social engineering in order to trick legitimate users into authorizing a malicious app as a form of persistence. A typical attack flow looks like this:

![image8.5](/img/huskycorp/oauthflow.png)

In this incident, the threat actor used a phishing email targeting `Lonnard@huskycorp.net` to obtain OAuth consent for a malicious application named `Calendar-Sync`. The email directed the user to an OAuth authorization endpoint requesting delegated Microsoft Graph permissions.

![image7](/img/huskycorp/calendar-syncemail.png)

The initial consent attempt was blocked by Microsoft security controls. This failure triggered an admin consent workflow, meaning a pending approval request was generated. An admin user ended up approving the consent request, adding `Calendar-Sync` as a service principal in the tenant.

![image8](/img/huskycorp/calendar-syncadded.png)
 
Once consent was granted, Entra ID issued refresh tokens to the application when `Lonnard@huskycorp.net` authenticated. 

![image9](/img/huskycorp/calendarsyncsignin.png)

After persistence was established, the attacker then used this access to exfiltrate sensitive business information, downloading several files from SharePoint.

![image10](/img/huskycorp/calendarsyncgraphapi.png)

![image11](/img/huskycorp/filedownloaded.png)

#### Inbox Rules
Using the privileges gained through `Calendar-Sync`, the attacker created a hidden inbox rule within `Lonnard@huskycorp.net`’s mailbox. The rule silently forwards emails containing the term “shareholder report” to an external ProtonMail address controlled by the attacker.

![image12](/img/huskycorp/messagerulesgraphapi.png)
![image13](/img/huskycorp/inboxrule.png)

Hidden inbox rules is a common Business Email Compromise (BEC) technique that allows attackers to stealthily exfiltrate data over time.

#### Application Ownership Abuse
Using credentials for the user `Ashlee@huskycorp.net`, previously obtained during the initial password spray, the attacker modified ownership and credentials for an existing Entra ID application named `TechDocuments`. The attacker added the compromised user as an application owner and created a new client secret for the application.

![image14](/img/huskycorp/techdocumentsapplication.png)

This technique allows attackers to authenticate as the application itself.

![image15](/img/huskycorp/techdocumentsignin.png)

#### Federated Domain Backdoor
The threat actor added a new federated domain, `huskyhelpdesk.store`, to the tenant. The domain was configured with a malicious issuer URI, enabling token issuance from an attacker-controlled identity provider.

![image16](/img/huskycorp/federateddomain.png)

By adding a federated domain, the attacker can redirect the authentication flow so that authentication is performed by the new federated domain rather than directly by the tenant itself. This means that the threat actor is able to impersonate any user without their credentials and bypassing MFA. 

![fed](/img/huskycorp/federatedbackdoor.png)

### Privilege Esclation

#### Managed Identity Abuse
The threat actor authenticated to the Azure virtual machine `HuskyVM` and leveraged the VM’s managed identity to access Azure resources. The attacker identified a Key Vault named `HuskyKey`. The attacker then assigned the `Key Vault Administrator` role to the managed identity at the Key Vault scope, effectively granting full control over secret management.

![img](/img/huskycorp/createroleassignment.png)


#### Key Vault Access
With administrative access to the Key Vault, the attacker listed available secrets and retrieved the value of a sensitive secret named `SecretKey`.
![alt text](/img/huskycorp/keyvaultaccess.png)

### On-Prem Compromise
After establishing control within the cloud identity plane, the attacker pivoted into the on-premises environment.
#### Internal Phish
The attacker initiated an internal phishing campaign by uploading a malicious document to SharePoint and distributing it to `Lonnard@huskycorp.net`. The email impersonated executive communications and prompted the user to open an attached archive file.

![alt](/img/huskycorp/internalphish.png)

The archive contained an ISO image with a malicious DLL and a shortcut file. When executed, the shortcut spawned `cmd.exe` and used `rundll32.exe` to trigger execution of the malicious DLL.

![alt](/img/huskycorp/lecmd.png)

#### DLL Execution and Credential Access
Following execution, the malicious DLL initiated outbound network connections over port `80` to a malicious IP and started local Office applications. 

![img](/img/huskycorp/officestarted.png)

Because Office applications automatically authenticate to Entra ID, access and refresh tokens were present in memory. The attacker dumped memory from these processes, producing `.dmp` files containing authentication artifacts. This technique enabled the attacker to extract tokens without needing to capture credentials directly, reducing reliance on password-based access.

![img](/img/huskycorp/officedump.png)


#### Domain Controller Access
Using stolen tokens and elevated privileges, the attacker moved laterally to the domain controller using Impacket’s `wmiexec.py.` This provided remote command execution under high-privilege context.

Once access was established, the attacker conducted reconnaissance, deployed additional tooling, and ultimately cleared Windows event logs and disabled Unified Audit Log ingestion. These actions were consistent with anti-forensic behavior intended to hinder incident response and obscure the full scope of the compromise.

#### PRT Theft
Further analysis revealed evidence of Primary Refresh Token (PRT) theft. A PRT is a user’s identity token that can be used to obtain new access tokens. `PTASpy` is a tool that extracts PRTs from memory in hybrid environments that use PTA. 

![alt](/img/huskycorp/ptaspyflow.png)

PRT theft allows attackers to mint new access tokens on demand across Entra-integrated services, effectively bypassing MFA and Conditional Access controls. This represents one of the most severe identity compromise techniques in hybrid Azure environments.
![alt](/img/huskycorp/ptaspy.png)

## Reconstructed Timeline

| Time (UTC)       | Event                                                                                                    | Evidence Source                       | Notes                                    |
| ---------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------- | ---------------------------------------- |
| 2024-04-20 21:57 | Multiple failed authentication attempts against `Ashlee`, `Lonnard`, and `lina` from IP `103.216.220.45` | Entra ID Sign-In Logs                 | Password spraying behavior               |
| 2024-04-20 22:36 | Successful credential validation for `Lonnard@huskycorp.net`                                             | Entra ID Sign-In Logs                 | Account uses Pass-Through Authentication |
| 2024-04-20 22:37 | Conditional Access blocks initial interactive sign-in attempts                                           | Entra ID Sign-In Logs                 | `ConditionalAccessFailed`                |
| 2024-04-20 22:41 | Successful sign-in from IP `146.70.196.180` using user agent `azurehound/v2.1.8`                         | Entra ID Sign-In Logs                 | Indicates tenant reconnaissance tooling  |
| 2024-04-20 22:42 | Microsoft Graph enumeration activity begins                                                              | Entra ID Audit Logs / Graph Telemetry | User, role, and application discovery    |
| 2024-04-20 23:05 | OAuth consent phishing email sent to `Lonnard@huskycorp.net`                                             | Exchange Message Trace                | Consent request for **Calendar-Sync**    |
| 2024-04-20 23:11 | Administrative consent granted for **Calendar-Sync**                                                     | Entra ID Audit Logs                   | Malicious service principal created      |
| 2024-04-20 23:14 | Non-interactive Microsoft Graph access via **Calendar-Sync**                                             | Entra ID Non-Interactive Sign-In Logs | OAuth-based persistence established      |
| 2024-04-20 23:21 | Hidden inbox rule created forwarding mail externally                                                     | Exchange Audit Logs                   | Mailbox persistence                      |
| 2024-04-20 23:34 | Attacker added as owner of **TechDocuments** application                                                 | Entra ID Audit Logs                   | Application ownership abuse              |
| 2024-04-20 23:47 | Federated domain `huskyhelpdesk.store` added to tenant                                                   | Entra ID Audit Logs                   | Tenant-level authentication backdoor     |
| 2024-04-21 00:12 | Authentication via attacker-controlled federated IdP                                                     | Entra ID Sign-In Logs                 | MFA and Conditional Access bypass        |
| 2024-04-21 01:03 | Managed identity on `HuskyVM` enumerates Azure resources                                                 | Azure Activity Logs                   | Workload identity abuse                  |
| 2024-04-21 01:09 | Managed identity granted **Key Vault Administrator** role                                                | Azure Activity Logs                   | Privilege escalation                     |
| 2024-04-21 01:12 | Secrets accessed and backed up from `HuskyKey` vault                                                     | Key Vault Diagnostics Logs            | Secret exfiltration                      |
| 2024-04-21 02:04 | Internal phishing document delivered via SharePoint                                                      | SharePoint Audit Logs                 | Pivot to on-premises                     |
| 2024-04-21 02:09 | Malicious LNK executed; DLL loaded via `rundll32.exe`                                                    | Windows Event Logs                    | Initial code execution                   |
| 2024-04-21 02:12 | Office applications spawned; memory dumps created                                                        | Host Artifacts                        | Token harvesting                         |
| 2024-04-21 02:31 | Lateral movement to domain controller via `wmiexec.py`                                                   | Security Logs                         | Remote command execution                 |
| 2024-04-21 02:36 | `PTASpy.dll` injected; Primary Refresh Token extracted                                                   | Host Artifacts / AADInternals         | Hybrid identity compromise               |
| 2024-04-21 02:41 | Windows event logs cleared on domain controller                                                          | Windows Event Logs                    | Anti-forensics                           |
| 2024-04-21 02:44 | Unified Audit Log ingestion disrupted                                                                    | Microsoft 365 Audit Logs              | Attempted evidence suppression           |


## Closing Notes
This incident demonstrates that modern attackers increasingly target identity rather than just exploiting traditional software vulnerabilities. Defending against these threats requires treating identity as a primary security boundary and implementing controls that limit persistence, visibility gaps, and privilege escalation across both cloud and on-premises environments.
