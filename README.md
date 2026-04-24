<div align="center">

# ActiveDirectory — SAST Detection Rules

**Static Application Security Testing rules for Active Directory attack techniques**

[![Rules](https://img.shields.io/badge/Detection%20Rules-80%2B-blue?style=flat-square)](.)
[![Techniques](https://img.shields.io/badge/MITRE%20ATT%26CK-45%2B%20Techniques-red?style=flat-square)](https://attack.mitre.org)
[![Severity](https://img.shields.io/badge/Critical%20Rules-30%2B-critical?style=flat-square)](.)
[![Format](https://img.shields.io/badge/Format-Sigma%20%2F%20YAML-orange?style=flat-square)](https://github.com/SigmaHQ/sigma)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20%7C%20Elastic%20%7C%20Sentinel-informational?style=flat-square)](.)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

<br/>

> Each rule maps an attack technique to Windows Event IDs, Sigma conditions, MITRE ATT&CK, and remediation guidance.  
> Designed for **blue teams**, **SOC analysts**, and **purple team** exercises.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Rule Files](#rule-files)
- [Rule Structure](#rule-structure)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Detection Categories](#detection-categories)
  - [Kerberos Attacks](#kerberos-attacks)
  - [Credential Dumping](#credential-dumping)
  - [Lateral Movement](#lateral-movement)
  - [ACL / ACE Abuse](#acl--ace-abuse)
  - [ADCS Certificate Abuse](#adcs-certificate-abuse-esc1-esc13)
  - [Persistence](#persistence)
  - [Coercion Attacks](#coercion-attacks)
  - [Trust Attacks](#trust-attacks)
  - [Password Attacks](#password-attacks)
  - [GPO Abuse](#gpo-abuse)
  - [EDR / AV Evasion](#edr--av-evasion)
  - [DCSync / DCShadow](#dcsync--dcshadow)
  - [RBCD Attacks](#rbcd-attacks)
  - [Tool Code Analysis](#tool-code-analysis)
- [Usage](#usage)
- [Key Event IDs Reference](#key-event-ids-reference)
- [Severity Definitions](#severity-definitions)
- [Disclaimer](#disclaimer)

---

## Overview

This directory contains **SAST-style detection rules** derived from the ADRedTeam attack modules. Each YAML file covers one attack category and provides:

- **Sigma-format detection conditions** — ready for SIEM import
- **Windows Event ID mappings** — exact event sources and field conditions
- **Sysmon detection rules** — process creation, network connections, image loads
- **MITRE ATT&CK technique IDs** — aligned to ATT&CK v14
- **Tool-specific indicators** — commands and patterns produced by ADRedTeam modules
- **Remediation guidance** — concrete hardening steps per technique
- **Code-level SAST findings** — security issues in the tool's own Python code

```
ActiveDirectory-SAST/
├── kerberos_attacks.yml      # AS-REP Roast, Kerberoast, Golden/Silver/Diamond Ticket
├── credential_dump.yml       # LSASS, SAM, NTDS, Mimikatz, Invoke-Mimi
├── lateral_movement.yml      # PSExec, WMI, Evil-WinRM, PtH, WinRS
├── acl_abuse.yml             # DCSync Grant, GenericAll, Shadow Credentials
├── cert_abuse.yml            # ESC1-ESC13, PKINIT, UnPAC-the-Hash
├── persistence.yml           # AdminSDHolder, DSRM, Skeleton Key, WMI Subscription
├── coercion_attacks.yml      # PrinterBug, PetitPotam, NTLM Relay, ADCS Relay
├── trust_attacks.yml         # ExtraSID, Cross-Forest Kerberoast, PAM Trust
├── password_attacks.yml      # Password Spraying, Kerbrute, Credential Stuffing
├── gpo_abuse.yml             # GPO Create/Link, GPP Passwords, Restricted Groups
├── edr_evasion.yml           # Defender Disable, AMSI Bypass, ETW Patch, Log Clear
├── dcsync_dcshadow.yml       # DCSync All/Targeted, DCShadow Rogue DC
├── rbcd_attacks.yml          # MAQ Full Chain, Bronze Bit, S4U2Self, Powermad
├── tool_sast_analysis.yml    # Global code security analysis + OPSEC review
└── README.md
```

## Rule Structure

Every rule follows a consistent YAML schema:

```yaml
title: ADRedTeam - [Category] Detection Rules
id: sast-[category]-001
status: production
mitre_attack:
  - T1XXX.XXX  # MITRE technique IDs

rules:
  - id: category-technique-001
    title: Human-readable rule name
    technique: T1XXX.XXX
    severity: critical | high | medium | low | info

    description: >
      What the attack does and why it is dangerous.

    event_sources:
      - windows_security_eventlog:
          event_ids: [XXXX]
          conditions:
            - field: FieldName
              value: "suspicious_value"
      - sysmon_eventlog:
          event_ids: [X]

    detection:
      sigma_condition: |
        EventID=XXXX AND Field="Value" AND count() > N within Xs

    tools_used:
      - "exact command from ADRedTeam module"

    false_positives:
      - Legitimate scenario that produces same events

    remediation:
      - Concrete hardening step

sast_code_analysis:          # Security issues in the tool's own Python code
  rules:
    - id: sast-code-XXX-001
      severity: high
      pattern: |
        regex_or_code_snippet
      description: What the issue is
      recommendation: How to fix it
```

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Sub-technique | Rule File |
|--------|-----------|--------------|-----------|
| Credential Access | T1003 | .001 LSASS Memory | `credential_dump.yml` |
| Credential Access | T1003 | .002 SAM | `credential_dump.yml` |
| Credential Access | T1003 | .003 NTDS | `credential_dump.yml`, `dcsync_dcshadow.yml` |
| Credential Access | T1003 | .004 LSA Secrets | `credential_dump.yml` |
| Credential Access | T1558 | .001 Golden Ticket | `kerberos_attacks.yml` |
| Credential Access | T1558 | .002 Silver Ticket | `kerberos_attacks.yml` |
| Credential Access | T1558 | .003 Kerberoasting | `kerberos_attacks.yml` |
| Credential Access | T1558 | .004 AS-REP Roasting | `kerberos_attacks.yml` |
| Credential Access | T1552 | .006 Group Policy Preferences | `gpo_abuse.yml` |
| Credential Access | T1555 | .004 Windows Credential Manager | `credential_dump.yml` |
| Credential Access | T1649 | — Steal/Forge Auth Certificates | `cert_abuse.yml` |
| Lateral Movement | T1021 | .001 RDP | `lateral_movement.yml` |
| Lateral Movement | T1021 | .002 SMB/Admin Shares | `lateral_movement.yml` |
| Lateral Movement | T1021 | .003 DCOM | `lateral_movement.yml` |
| Lateral Movement | T1021 | .006 WinRM | `lateral_movement.yml` |
| Lateral Movement | T1047 | — WMI | `lateral_movement.yml` |
| Lateral Movement | T1550 | .002 Pass the Hash | `lateral_movement.yml` |
| Lateral Movement | T1550 | .003 Pass the Ticket | `kerberos_attacks.yml` |
| Persistence | T1078 | .002 Domain Accounts (DSRM) | `persistence.yml` |
| Persistence | T1098 | — Account Manipulation | `acl_abuse.yml`, `persistence.yml` |
| Persistence | T1134 | .001 Unconstrained Delegation | `kerberos_attacks.yml`, `coercion_attacks.yml` |
| Persistence | T1134 | .005 SID-History Injection | `persistence.yml`, `trust_attacks.yml` |
| Persistence | T1207 | — Rogue Domain Controller | `dcsync_dcshadow.yml` |
| Persistence | T1484 | .001 Domain Policy Modification (GPO) | `gpo_abuse.yml` |
| Persistence | T1546 | .003 WMI Event Subscription | `persistence.yml` |
| Persistence | T1547 | .001 Registry Run Keys | `persistence.yml`, `gpo_abuse.yml` |
| Persistence | T1547 | .005 Security Support Provider | `persistence.yml` |
| Persistence | T1556 | .001 Domain Controller Authentication | `persistence.yml` |
| Persistence | T1556 | .006 Multi-Factor Authentication (Shadow Creds) | `acl_abuse.yml`, `coercion_attacks.yml` |
| Defense Evasion | T1055 | .012 Process Hollowing | `edr_evasion.yml` |
| Defense Evasion | T1059 | .001 PowerShell (AMSI Bypass) | `edr_evasion.yml` |
| Defense Evasion | T1070 | — Indicator Removal | `edr_evasion.yml`, `rbcd_attacks.yml` |
| Defense Evasion | T1562 | .001 Disable/Modify Security Tools | `edr_evasion.yml` |
| Defense Evasion | T1562 | .002 Disable Windows Event Logging | `edr_evasion.yml` |
| Discovery | T1087 | .002 Domain Account Enumeration | `acl_abuse.yml`, `trust_attacks.yml` |
| Discovery | T1589 | .001 Username Enumeration | `password_attacks.yml` |
| Collection | T1557 | — Adversary-in-the-Middle | `coercion_attacks.yml`, `password_attacks.yml` |
| Collection | T1557 | .001 LLMNR/NBT-NS Poisoning | `password_attacks.yml` |
| Impact | T1110 | .003 Password Spraying | `password_attacks.yml` |
| Impact | T1110 | .004 Credential Stuffing | `password_attacks.yml` |

---

## Detection Categories

### Kerberos Attacks

**File:** [`kerberos_attacks.yml`](kerberos_attacks.yml)

Covers the full Kerberos attack chain from hash collection to advanced ticket forgery.

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `kerberos-asrep-roast-001` | T1558.004 | Event 4768 with TicketEncryptionType=0x17 and PreAuthType=0 from non-DC |
| `kerberos-kerberoast-001` | T1558.003 | Bulk 4769 events with RC4 encryption (>5 in 30s) from same source |
| `kerberos-ptt-001` | T1550.003 | KRB5CCNAME env var, .kirbi/.ccache files, Rubeus ptt command |
| `kerberos-golden-ticket-001` | T1558.001 | TGT lifetime >10h, 4769 without prior 4768, RC4 when AES enforced |
| `kerberos-silver-ticket-001` | T1558.002 | Service ticket with no DC-side TGT event, PAC validation failure |
| `kerberos-diamond-ticket-001` | T1558.001 | Rubeus `diamond` in command line, /tgtdeleg flag, anomalous PAC SIDs |
| `kerberos-unconstrained-delegation-001` | T1134.001 | spoolsv.exe / lsass.exe outbound SMB to non-DC, forwardable TGT on workstation |
| `kerberos-constrained-delegation-001` | T1134.001 | S4U2Self + S4U2Proxy sequence, getST / Rubeus s4u in command line |

**Critical Event IDs:** 4768, 4769, 4624 (LogonType=9), 4672

---

### Credential Dumping

**File:** [`credential_dump.yml`](credential_dump.yml)

Detection for all major credential extraction paths — both remote (Linux attacker) and local (Windows Mimikatz).

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `credump-lsass-001` | T1003.001 | Sysmon Event 10: lsass.exe TargetImage with GrantedAccess 0x1010/0x1410/0x143a |
| `credump-lsass-invoke-mimi-001` | T1003.001 | PS ScriptBlock 4104 containing `sekurlsa::`, `lsadump::`, `vault::` keywords |
| `credump-sam-001` | T1003.002 | Registry access to `\REGISTRY\MACHINE\SAM` by non-SYSTEM account |
| `credump-ntds-dcsync-001` | T1003.003 | Event 4662 with replication GUIDs from non-DC source IP |
| `credump-lsa-secrets-001` | T1003.004 | SECURITY hive access — `\REGISTRY\MACHINE\SECURITY\Policy\Secrets` |
| `credump-laps-001` | T1552.006 | Event 4662 with `ms-Mcs-AdmPwd` in Properties by unauthorized account |
| `credump-ekeys-001` | T1003.001 | ScriptBlock containing `sekurlsa::ekeys` or SafetyKatz LSASS access |
| `credump-vault-001` | T1555.004 | ScriptBlock containing `vault::cred`, `token::elevate`, `PasswordVault` |

**Critical Event IDs:** 4662 (replication GUIDs), Sysmon 10 (lsass), 4104 (PS logging)

---

### Lateral Movement

**File:** [`lateral_movement.yml`](lateral_movement.yml)

Covers all common lateral movement primitives used in Windows environments.

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `lateral-psexec-001` | T1021.002 | Event 7045: random-named service in temp directory, deleted within seconds |
| `lateral-wmiexec-001` | T1047 | Sysmon 1: cmd.exe/powershell.exe child of WmiPrvSE.exe |
| `lateral-evil-winrm-001` | T1021.006 | WinRM Events 91/168, network logon type 3 on port 5985 |
| `lateral-dcom-001` | T1021.003 | mmc.exe with `-Embedding` spawned by svchost.exe |
| `lateral-pth-001` | T1550.002 | Event 4624 LogonType=9 with NTLM auth package |
| `lateral-winrs-001` | T1021.006 | winrshost.exe spawning cmd.exe / powershell.exe (Sysmon 1) |
| `lateral-atexec-001` | T1053.005 | Events 4698+4699 paired within 60s, GUID-format task name |
| `lateral-rdp-pth-001` | T1021.001 | Event 4624 LogonType=10 with NTLM authentication |

**Critical Event IDs:** 7045, 4624 (type 3/9/10), Sysmon 1 (WmiPrvSE parent), 91/168 (WinRM)

---

### ACL / ACE Abuse

**File:** [`acl_abuse.yml`](acl_abuse.yml)

Detection for misused Active Directory access control entries.

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `acl-dcsync-grant-001` | T1484.001 | Event 5136: nTSecurityDescriptor change with DS-Replication GUID added |
| `acl-group-addmember-001` | T1098 | Events 4728/4732/4756: member added to DA/EA/Schema Admins by non-DA |
| `acl-forcechangepassword-001` | T1098 | Event 4724: subject != target, neither is admin |
| `acl-shadow-credentials-001` | T1556.006 | Event 5136: `msDS-KeyCredentialLink` Value Added by non-SYSTEM |
| `acl-add-computer-001` | T1098.001 | Event 4741: computer account created by non-admin (MAQ abuse) |
| `acl-laps-read-001` | T1552.006 | Event 4662: `ms-Mcs-AdmPwd` accessed by unauthorized account |
| `acl-bloodhound-001` | T1087.002 | >1000 Event 4662 from same user within 60s (bulk LDAP ACL enumeration) |

**Critical Event IDs:** 5136 (AD attribute change), 4728/4732/4756 (group membership), 4741 (computer created)

---

### ADCS Certificate Abuse (ESC1-ESC13)

**File:** [`cert_abuse.yml`](cert_abuse.yml)

Comprehensive coverage of Active Directory Certificate Services misconfigurations.

| Rule ID | ESC | Description | Key Detection |
|---------|-----|-------------|--------------|
| `cert-esc1-001` | ESC1 | Requestor-supplied SAN enrollment | Event 4887: SAN differs from requestor identity |
| `cert-esc4-001` | ESC4 | Template ACL overwrite | Event 5136: `pKICertificateTemplate` class modified |
| `cert-esc6-001` | ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag | Event 4887: SubCA template with cross-identity SAN |
| `cert-esc8-001` | ESC8 | NTLM relay to ADCS HTTP enrollment | IIS log: `POST /certsrv/certfnsh.asp` with NTLM auth |
| `cert-esc9-001` | ESC9 | No szOID_NTDS_CA_SECURITY_EXT binding | Certificate without OID 1.3.6.1.4.1.311.25.2 |
| `cert-esc11-001` | ESC11 | RPC enrollment without encryption | Missing IF_ENFORCEENCRYPTICERTREQUEST flag |
| `cert-pkinit-001` | — | Certificate used for Kerberos pre-auth | Event 4768 with populated CertIssuerName field |
| `cert-enum-001` | — | Template enumeration (certipy find) | Bulk 4662 on `pKICertificateTemplate` objects |

**Key Principle:** ESC8 + ESC1 are the most commonly exploited. Alert on Event 4887 immediately for cross-identity certificate issuance.

---

### Persistence

**File:** [`persistence.yml`](persistence.yml)

Covers both domain-level and local persistence mechanisms.

| Rule ID | Technique | Persistence Type | Key Detection |
|---------|-----------|-----------------|--------------|
| `persist-adminsdholder-001` | T1098 | Domain | Event 5136 on `CN=AdminSDHolder,CN=System` object |
| `persist-dsrm-001` | T1078.002 | Domain | Registry: `DSRMAdminLogonBehavior = 2` (Event 4657) |
| `persist-skeleton-key-001` | T1556.001 | Domain | Sysmon 10: LSASS access with 0x1fffff mask + `misc::skeleton` in PS |
| `persist-custom-ssp-001` | T1547.005 | Domain | Registry: `Security Packages` key modified to include `mimilib` |
| `persist-sid-history-001` | T1134.005 | Domain | Events 4765/4766: SID History added to user account |
| `persist-wmi-subscription-001` | T1546.003 | Local | Sysmon 21: `CommandLineEventConsumer` binding created |
| `persist-registry-runkey-001` | T1547.001 | Local | Event 4657: Run key write in `CurrentVersion\Run` |
| `persist-network-provider-001` | T1556 | Local | Registry: `NetworkProvider\Order` modified (Event 4657) |
| `persist-delegation-backdoor-001` | T1098 | Domain | Event 5136: `msDS-AllowedToDelegateTo` modified |

---

### Coercion Attacks

**File:** [`coercion_attacks.yml`](coercion_attacks.yml)

Detection for forced authentication attacks used to capture hashes or relay credentials.

| Rule ID | Protocol | Method | Key Detection |
|---------|----------|--------|--------------|
| `coerce-printerbug-001` | MS-RPRN | SpoolSample | Sysmon 3: `spoolsv.exe` outbound SMB to non-DC |
| `coerce-petitpotam-001` | MS-EFSRPC | EfsRpcOpenFileRaw | Sysmon 3: `lsass.exe` outbound SMB to non-DC |
| `coerce-dfscoerce-001` | MS-DFSNM | NetrDfsAddStdRoot | RPC to interface `4fc742e0-...` from external host |
| `coerce-coercer-001` | Multi | All methods | Multiple RPC interface calls from same IP within 60s |
| `coerce-responder-001` | LLMNR/NBT-NS | Poisoning | LLMNR response from non-DC host (port 5355) |
| `coerce-ntlm-relay-ldap-001` | LDAP | ntlmrelayx | Event 4741: computer account created by another computer account |
| `coerce-ntlm-relay-adcs-001` | HTTP/ADCS | ESC8 relay | Event 4887: DC cert requested from non-DC machine |
| `coerce-shadow-cred-relay-001` | LDAP | --shadow-credentials | Event 5136: `msDS-KeyCredentialLink` modified by computer account |
| `coerce-unconstrained-tgt-001` | Kerberos | TGT Capture | Event 4768 forwardable TGT to non-DC + Rubeus monitor |

**Highest Impact Chain:** `PetitPotam → NTLM Relay ADCS → certipy auth → DCSync` — full domain compromise in minutes.

---

### Trust Attacks

**File:** [`trust_attacks.yml`](trust_attacks.yml)

Cross-forest and cross-domain attack detection.

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `trust-cross-forest-kerberoast-001` | T1558.003 | Cross-realm 4769 with RC4 encryption |
| `trust-extrasid-001` | T1558.001 | PAC SID containing -519 (EA) from child domain account |
| `trust-key-extraction-001` | T1003.003 | `lsadump::trust` in ScriptBlock / secretsdump on trust accounts |
| `trust-pam-001` | T1484.002 | Bastion forest account authenticating to production sensitive resources |
| `trust-enumeration-001` | T1087.002 | Bulk 4662 on `trustedDomain` objects |
| `trust-foreign-group-001` | T1087.002 | Bulk 4662 on `foreignSecurityPrincipal` objects |
| `trust-child-parent-001` | T1134.005 | Inter-realm TGT with parent domain SID in SIDHistory field |

---

### Password Attacks

**File:** [`password_attacks.yml`](password_attacks.yml)

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `password-spray-001` | T1110.003 | >10 distinct usernames failing with SubStatus=0xC000006A from same IP within 30min |
| `password-kerbrute-enum-001` | T1589.001 | Bulk 4768 errors (0x6 / 0x18) from single source within 60s |
| `password-ntlm-relay-001` | T1557 | Event 4624 type 3 NTLM from LLMNR-poisoned host |
| `password-credential-stuffing-001` | T1110.004 | Each unique username tested once — distinct from brute force pattern |
| `password-default-creds-001` | T1078.001 | Event 4624 type 3 for `administrator`/`admin`/`guest` from unknown host |

**Spray Detection Formula:** `count(distinct TargetUserName) by SourceIP > 10 within 30min AND failures_per_user < 3`

---

### GPO Abuse

**File:** [`gpo_abuse.yml`](gpo_abuse.yml)

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `gpo-create-link-001` | T1484.001 | Event 5137: new `groupPolicyContainer` object created by non-admin |
| `gpo-runkey-001` | T1547.001 | New `Registry.xml` in `SYSVOL\Policies\*\Machine\Preferences\Registry` |
| `gpo-scheduled-task-001` | T1053.005 | New `ScheduledTasks.xml` in SYSVOL — SharpGPOAbuse pattern |
| `gpo-restricted-groups-001` | T1098.001 | `GptTmpl.inf` modified with `[Group Membership]` section |
| `gpo-gpp-passwords-001` | T1552.006 | SYSVOL access to `Groups.xml`/`Services.xml`/`ScheduledTasks.xml` (bulk) |
| `gpo-delegation-enum-001` | T1087.002 | Bulk 4662 on `groupPolicyContainer` objects |

**Quick Win:** Search SYSVOL for `cpassword` — if present, credentials are immediately crackable:
```powershell
findstr /s /i cpassword \\<domain>\sysvol\<domain>\policies\
```

---

### EDR / AV Evasion

**File:** [`edr_evasion.yml`](edr_evasion.yml)

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `edr-defender-disable-001` | T1562.001 | Windows Defender Event 5001 (protection disabled) — **alert immediately** |
| `edr-safetykatz-001` | T1003.001 | `Loader.exe` network connection to `127.0.0.1:8080` for `.exe` download |
| `edr-amsi-bypass-001` | T1059.001 | ScriptBlock 4104 containing `AmsiScanBuffer` / `amsi.dll` / patch bytes |
| `edr-etw-patch-001` | T1562.006 | ScriptBlock containing `EtwEventWrite` patch or ntdll modification |
| `edr-ntdll-unhook-001` | T1055 | Sysmon 7: `ntdll.dll` loaded from non-standard path |
| `edr-nanodump-001` | T1003.001 | Sysmon 10: LSASS access with 0x1fffff mask from nanodump process |
| `edr-clear-logs-001` | T1562.002 | Event 1102 (Security log cleared) — **always forward logs to SIEM first** |
| `edr-runasppl-disable-001` | T1562.001 | Event 4657: `RunAsPPL` registry value set to 0 |

---

### DCSync / DCShadow

**File:** [`dcsync_dcshadow.yml`](dcsync_dcshadow.yml)

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `dcsync-all-hashes-001` | T1003.003 | Event 4662 with `1131f6ad` GUID from non-DC source → **CRITICAL** |
| `dcsync-targeted-001` | T1003.003 | Event 4662 with replication GUID targeting `krbtgt`/`Administrator` |
| `dcsync-dcshadow-001` | T1207 | New `nTDSDSA` object in `CN=Configuration` from non-DC machine |
| `dcsync-rights-check-001` | T1087.002 | 4662 read access on DS-Replication ACEs by non-DA account |

**DCSync Detection GUID Reference:**

| GUID | Right |
|------|-------|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All (**most critical**) |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

---

### RBCD Attacks

**File:** [`rbcd_attacks.yml`](rbcd_attacks.yml)

| Rule ID | Technique | Key Detection |
|---------|-----------|--------------|
| `rbcd-full-chain-001` | T1134.001 | Event 4741 → Event 5136 (`msDS-AllowedToActOnBehalfOfOtherIdentity`) within 30min |
| `rbcd-ntlm-relay-001` | T1557 | Computer account ($) creating another computer account AND modifying delegation attribute |
| `rbcd-bronze-bit-001` | T1134.001 | S4U2Proxy with non-forwardable service ticket (CVE-2020-17049) |
| `rbcd-s4u2self-001` | T1134.001 | Event 4769: ServiceName == TargetUser (self-service-ticket request) |
| `rbcd-cleanup-001` | T1070 | Event 5136: `msDS-AllowedToActOnBehalfOfOtherIdentity` Value Deleted |
| `rbcd-powermad-001` | T1136.002 | ScriptBlock 4104 containing `New-MachineAccount` / `Powermad` |

**#1 Prevention:** Set `MachineAccountQuota = 0` — eliminates the entire MAQ-based RBCD attack surface:
```powershell
Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}
```

---

### Tool Code Analysis

**File:** [`tool_sast_analysis.yml`](tool_sast_analysis.yml)

Static analysis of the ADRedTeam tool's own Python codebase.

| Finding ID | Severity | Issue |
|------------|----------|-------|
| `GLOBAL-CRIT-001` | Critical | `run_cmd()` may use `shell=True` — command injection via user input |
| `GLOBAL-CRIT-002` | Critical | Passwords with `'`, `` ` ``, `$` break f-string command construction |
| `GLOBAL-HIGH-001` | High | `.env` stores plaintext credentials on filesystem |
| `GLOBAL-HIGH-002` | High | SESSION dict caches credentials for entire session (no timeout) |
| `GLOBAL-HIGH-003` | High | Output files written to world-readable `/tmp` with predictable names |
| `GLOBAL-HIGH-004` | High | NTLM hashes / Kerberos ticket paths visible in process list |
| `GLOBAL-HIGH-005` | High | No input validation on target IP/hostname |
| `GLOBAL-MED-001` | Medium | Tool may require root unnecessarily |
| `GLOBAL-MED-002` | Medium | Python dependencies may be outdated (check with `pip-audit`) |
| `GLOBAL-MED-003` | Medium | No confirmation prompts before high-blast-radius operations |
| `GLOBAL-MED-004` | Medium | Session log may contain cleartext credentials |

---

## Usage

### Who Uses These Rules and How

| Role | What They Do | How |
|------|-------------|-----|
| **SOC Analyst** | Import rules → automatic alerts fire when attacks occur | Sigma → SIEM |
| **Blue Team Lead** | Find missing audit policies, run hardening checklist | `remediation` sections |
| **Incident Responder** | Search past logs for attack timeline after a breach | `sigma_condition` as hunting queries |
| **Purple Team** | Red team attacks, blue team validates detection coverage | Run ADRedTeam module → check if rule triggers |
| **Threat Hunter** | Proactive daily searches before alerts fire | `sigma_condition` as scheduled queries |
| **Tool Developer** | Scan own pentest tool code for injection / credential issues | Semgrep + `sast_code_analysis` patterns |

---

### 1 — SIEM Integration (Sigma → Alert)

Convert rules to your SIEM's native query language with [sigma-cli](https://github.com/SigmaHQ/sigma):

```bash
pip install sigma-cli

sigma convert -t splunk        kerberos_attacks.yml    # Splunk SPL
sigma convert -t eql           credential_dump.yml     # Elastic EQL
sigma convert -t azure-monitor lateral_movement.yml    # Sentinel KQL
sigma convert -t qradar        acl_abuse.yml           # QRadar AQL

# Convert all rules at once
for f in *.yml; do sigma convert -t splunk "$f"; done
```

Each exported query becomes a **saved search / detection rule** in your SIEM. When the condition triggers, your SIEM fires an alert automatically.

---

### 2 — Purple Team Exercise

Run an ADRedTeam module on an authorized lab, then verify the matching rule fires:

```
Red Team  →  kerberos_attacks.py option [2] (Kerberoast)
Blue Team →  check SIEM for rule kerberos-kerberoast-001
             condition: EventID=4769 AND EncryptionType=0x17 AND count > 5 within 30s

Result: triggered  ✅  →  detection works
        no alert   ❌  →  audit policy or log source missing
```

Use the `remediation` section of each rule as your fix list when detection fails.

---

### 3 — Incident Response — Hunt Past Logs

After a suspected breach, use the `sigma_condition` fields as PowerShell queries to search historical events:

```powershell
# Was DCSync performed? (last 7 days)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662; StartTime=(Get-Date).AddDays(-7)} |
  Where-Object { $_.Message -match "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }

# Was Security log cleared?
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}

# Were any computer accounts created by non-admins?
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4741} |
  Where-Object { $_.Message -notmatch "SYSTEM" }
```

---

### 4 — Hardening Checklist

Every rule's `remediation` block is a concrete hardening action. Work through them category by category:

```
kerberos_attacks.yml   →  Reset krbtgt twice · Enable Protected Users · Enforce AES256 · Apply KB5008380
acl_abuse.yml          →  Set MachineAccountQuota=0 · Audit msDS-KeyCredentialLink · Review AdminSDHolder ACL
cert_abuse.yml         →  Remove ESC flags · Enable HTTPS on ADCS · Require Kerberos for enrollment
coercion_attacks.yml   →  Disable Print Spooler on DCs · Enable LDAP signing · Block SMB outbound from DCs
edr_evasion.yml        →  Enable Tamper Protection · Deploy Credential Guard · Forward logs to SIEM first
```

---

### 5 — Code Analysis (Semgrep)

Use the `sast_code_analysis` patterns to scan your own pentest tool code:

```bash
pip install semgrep

# Scan a Python tool for shell injection, credential exposure
semgrep --config . /path/to/your/tool/

# Check only high/critical findings
semgrep --config . --severity ERROR /path/to/your/tool/
```

The patterns catch common issues: `shell=True` injection, plaintext passwords in command strings, credential output to world-readable `/tmp`, and NTLM hashes visible in process arguments.

---

### Manual Review Checklist (Post-Engagement)

```
□ Delete /tmp/ntds_hashes*, /tmp/asrep.txt, /tmp/kerberoast.txt and other output files
□ Check output/*.log for credential exposure before archiving
□ Rotate .env credentials — never reuse across engagements
□ Verify MachineAccountQuota was reset to 0 on target
□ Confirm DCSync rights remediation (Event 4662 monitoring active)
□ Confirm AdminSDHolder ACL reviewed after persistence testing
□ Check ADCS templates patched after cert_abuse module use
```

---

## Key Event IDs Reference

| Event ID | Log | Description | Priority |
|----------|-----|-------------|----------|
| **1102** | Security | Security log cleared | CRITICAL — alert immediately |
| **4662** | Security | Object access (DS-Replication GUIDs = DCSync) | CRITICAL if from non-DC |
| **4688** | Security | Process creation (requires audit policy) | HIGH |
| **4697** | Security | Service installation | HIGH |
| **4724** | Security | Password reset attempt | HIGH if cross-account |
| **4728** | Security | Member added to global group | HIGH for privileged groups |
| **4741** | Security | Computer account created | MEDIUM (HIGH if by non-admin) |
| **4768** | Security | Kerberos TGT request | MEDIUM (pattern analysis needed) |
| **4769** | Security | Kerberos service ticket request | MEDIUM (RC4 = HIGH) |
| **5136** | Security | AD object attribute modified | CRITICAL for sensitive attributes |
| **5137** | Security | AD object created | HIGH for GPO/computer objects |
| **7045** | System | Service installed | HIGH for random-named services |
| **Sysmon 1** | Sysmon | Process creation with command line | HIGH |
| **Sysmon 3** | Sysmon | Network connection | HIGH for lsass.exe / spoolsv.exe outbound |
| **Sysmon 10** | Sysmon | Process access (LSASS target = HIGH) | CRITICAL |
| **Sysmon 19-21** | Sysmon | WMI event subscription | HIGH |
| **Sysmon 25** | Sysmon | Process tampering | HIGH |

---


## Recommended Audit Policies

Enable these Windows audit policies to generate the events referenced in these rules:

```
Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy:

Account Logon:
  ✅ Audit Kerberos Authentication Service  → Success, Failure
  ✅ Audit Kerberos Service Ticket Operations → Success, Failure

Account Management:
  ✅ Audit Computer Account Management  → Success
  ✅ Audit Security Group Management    → Success
  ✅ Audit User Account Management      → Success, Failure

DS Access:
  ✅ Audit Directory Service Access     → Success, Failure
  ✅ Audit Directory Service Changes    → Success

Logon/Logoff:
  ✅ Audit Logon                        → Success, Failure
  ✅ Audit Special Logon                → Success

Object Access:
  ✅ Audit Kernel Object                → Success, Failure (for LSASS)
  ✅ Audit Registry                     → Success, Failure

Policy Change:
  ✅ Audit Audit Policy Change          → Success

System:
  ✅ Audit Security System Extension    → Success
  ✅ Audit System Integrity             → Success, Failure
```

---

## Recommended Sysmon Configuration

These Sysmon event IDs are referenced across multiple rules. Use a comprehensive Sysmon config such as [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) and ensure the following event types are enabled:

| Sysmon ID | Event | Required For |
|-----------|-------|-------------|
| 1 | Process Create | lateral_movement, edr_evasion, gpo_abuse |
| 3 | Network Connect | coercion_attacks, kerberos_attacks |
| 7 | Image Loaded | edr_evasion (ntdll unhooking) |
| 10 | Process Access | credential_dump (LSASS) |
| 13 | Registry Value Set | persistence |
| 19-21 | WMI Events | persistence |
| 25 | Process Tampering | edr_evasion |

---

## Disclaimer

> These detection rules are published for **defensive, educational, and authorized purple team purposes only**.  
> The techniques described are based on publicly documented Active Directory attack research.  
> Rules are derived from the ADRedTeam red team framework — which itself is for **authorized penetration testing only**.  
>  
> - Do not use these indicators to identify attack techniques for offensive purposes  
> - Always validate detection rules in a lab environment before production deployment  
> - False positive rates vary significantly depending on your environment baseline  
> - Some rules require Sysmon deployment — see the [Sysmon configuration section](#recommended-sysmon-configuration) above  

---

<div align="center">

**ADRedTeam SAST Rules** · Built for Blue Teams · Powered by tmrswrr Research

[Report an Issue](https://github.com/capture0x/ActiveDirectory-SAST/issues) · [MITRE ATT&CK](https://attack.mitre.org)

</div>
