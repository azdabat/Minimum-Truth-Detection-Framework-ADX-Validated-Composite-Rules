# Advanced Defense Evasion & C2 Detection Pack
### Author: Ala Dabat
### Version: 2025-11
### Components:
- AMSI Bypass & Memory-Dumping LOLBin Detection
- Suspicious Ports C2 Detector (Hybrid Jitter Analysis)
- Suspicious Ports Detector (Static Port Surface)

---

## Overview

This rulepack focuses on two high-value intrusion surfaces:

1. **Defense Evasion**  
   - AMSI bypasses  
   - Memory dumping  
   - LOLBin-based execution  
   - Service tampering  

2. **Command & Control (C2)**  
   - Suspicious ports from a curated external list  
   - Hybrid time-interval jitter detection  
   - Process/service attribution  
   - Port metadata and behavioural scoring  

The goal is to expose the two most common stages in real intrusions:
- **Stage 2: Defense Evasion (LOLBins, AMSI bypass, memory access)**
- **Stage 3: C2 Establishment (initial callback, beaconing, tunnels)**

These rules are designed to be run in Microsoft Defender Advanced Hunting or Sentinel KQL.

---

# 1. AMSI Bypass & Memory Dumping Detection Rule
### Detection Surface
This rule highlights:
- AMSI bypass strings
- Encoded PowerShell commands
- LSASS memory dumping (comsvcs.dll)
- LOLBins used for code execution or in-memory stagers
- Service termination to disable AV/EDR
- Base64 and encoded payloads
- Command-line indicators tied to real attacker behaviour

### Threat Focus
The rule targets common red-team and malware behaviour:
- PowerShell AMSI bypasses  
- Encoded second-stage loaders  
- Memory dumping tactics used by credential theft tooling  
- LOLBin stagers (mshta, rundll32, regsvr32, wmic, certutil, bitsadmin)  
- Scripts downloaded and executed in-memory  

### Why It Works
Most attackers depend on LOLBins because:
- They are preinstalled  
- They evade naive allowlists  
- Many bypasses are trivial to embed  
- AMSI bypasses are easily mutated but not deeply obfuscated  

This rule is built around **behavioural analysis**, not signatures.

---

# 2. Suspicious Ports + Hybrid Jitter C2 Detection Rule
### Detection Surface
This rule extends classical suspicious-port detection into a C2-focused engine.

It uses:
- External suspicious port feed  
- Process attribution  
- Connection volume  
- Timing intervals  
- Jitter computation  
- Connection periodicity behaviour  
- Port metadata  

### Why It Is Effective
Modern C2 infrastructure rarely beacons at fixed intervals.
Sliver, Cobalt Strike, Havoc, Brute Ratel, Empire, Mythic all use jitter.

Detecting:
- **Avg interval**
- **Std deviation**
- **Ratio drift**
- **Repeated burst patterns**

provides high-fidelity detection with low false positives.

---

# 3. Suspicious Ports (Static Detector)
This is the baseline detector with:
- External port feed matching  
- Connection count  
- Basic scoring  
- No jitter behaviour  
- Direct process attribution  

This rule is fast, lightweight, and useful as a raw surface or pivot for threat hunters.

---

# Differences Between the C2 Rules

| Capability | Static Ports Rule | Jitter C2 Rule |
|-----------|-------------------|----------------|
| External suspicious port list | Yes | Yes |
| C2 detection | Basic | Advanced |
| Detection of modern frameworks | Weak | Strong |
| Jitter analysis | No | Yes |
| Process attribution | Yes | Yes |
| Summaries & directives | Yes | Yes |
| Behavioural scoring | Limited | Extensive |
| Usefulness in large tenants | High | High |
| Usefulness for DFIR | Medium | High |
| Detects low-and-slow beacons | No | Yes |
| Detects fallback channels | No | Yes |
| Covers encrypted tunnels | Partial | Strong |

---

# Threat Hunting Matrix

## A. What These Rules Catch

| Threat Type | AMSI Rule | C2 Static | C2 Jitter | Notes |
|-------------|-----------|-----------|-----------|-------|
| AMSI bypass (AmsiScanBuffer) | Yes | No | No | Behavioural string match |
| Encoded PowerShell | Yes | No | No | Base64, -enc |
| Memory dumping (comsvcs.dll) | Yes | No | No | LSASS extraction |
| LOLBin stagers | Yes | No | No | mshta, rundll32 |
| Ransomware loader download | Yes | Yes | Yes | DNS/HTTP rare ports |
| Cobalt Strike beaconing | No | Weak | Strong | Jitter catches it |
| Sliver beaconing | No | Weak | Strong | Sliding/drift intervals |
| Havoc C2 | No | Partial | Strong | Jitter detection |
| Brute Ratel | No | No | Strong | Tends to low jitter |
| Reverse shells | No | Yes | Yes | Rare ports, jitter optional |
| Encrypted tunnels | No | Partial | Strong | OpenVPN/1194 |
| Proxy pivots | No | Partial | Strong | 1080, 9050 |
| RMM misuse (ScreenConnect etc.) | No | Partial | Strong | Repeated tunneling |
| Stagers on weird ports | No | Yes | Yes | Capture all ports in feed |

---

## B. What These Rules Do Not Catch

| Missed Category | Reason |
|-----------------|--------|
| QUIC-based C2 | Port-hiding, requires QUIC context |
| DNS-over-HTTPS C2 | Masquerades under HTTPS |
| ICMP-based C2 | No port involved |
| Full in-memory implants with no network | No outbound/inbound events |
| VM guest-to-host pivoting | Not visible at OS layer |
| Browser-based WASM implants | Require HTTP header detection |
| Bluetooth/WiFi side-channel C2 | Out of telemetry scope |

---

# Known Threats & CVEs Covered Indirectly

**Defense Evasion / AMSI Bypass**
- CVE-2023-21761 (AMSI bypass vector)
- CVE-2022-41076 (PowerShell exposed bypass path)
- Numerous AMSI mutations used by Cobalt Strike and QakBot loaders

**Memory Dumping / Credential Theft**
- Techniques associated with:
  - TrickBot  
  - QakBot  
  - Emotet  
  - LockBit  
  - Hive  
  - Conti leaks-derived tooling  

**C2 Ports / Tunneling Tools**
- Sliver default ports: 8888, 31337, custom
- Havoc: 40056, 5040
- Cobalt Strike: 80, 443, 4444, 50050
- Mythic: 7443, custom high ports
- Empire: 8080, 8443
- Brute Ratel: random high ports
- Meterpreter: 4444, 8081, 7777
- Reverse SSH tunnels: 7000+, 2222
- Socks5 proxies: 1080
- OpenVPN C2 transport: 1194
- WinRM lateral movement: 5985/5986
- RDP pivoting: 3389

**Driver-Based C2 / Service Tunnels**
No direct CVEs but commonly tied to:
- Bring-Your-Own-Vulnerable-Driver (BYOVD) chains
- Red-team service tunneling via signed vendors

---

# Combined Operational Workflow for Analysts

### 1. AMSI Rule Fires  
Investigate:
- Encoded loader  
- Memory write operations  
- AMSI bypass strings  
- LOLBin invocation  
- Parent-child process chain  

If follow-on network activity exists → pivot into the C2 rules.

---

### 2. Static Port Rule Fires  
Investigate:
- Process owner  
- Command-line  
- Port metadata  
- Number of connections  
- Reputation of destination  

If it appears repetitive → check jitter rule.

---

### 3. Jitter Rule Fires  
Investigate:
- Interval statistics  
- Jitter ratio  
- Behavioural C2 patterns  
- Service or binary legitimacy  
- Account/session context  

If JitterRatio > ~0.10 → treat as likely C2.

---


---

# Analyst Notes

These rules provide:
- Full process-level attribution
- Defence evasion detection
- C2 behavioural detection
- Low noise, high fidelity
- Strong pivot paths for DFIR
- Coverage for modern red-team tradecraft
- No reliance on external TI tables

This is a mature, reproducible, production-minded rulepack suitable for use in:
- SOC L2.5–L3
- Threat Hunting Teams
- DFIR engagements
- Purple-team labs
- Supply-chain risk assessments

---
~~~
██████████████████████████████████████████████████████████████████████████████████████
█                               MITRE ATT&CK HEATMAP                                 █
█          Coverage: AMSI / LOLBins Evaders + Suspicious Port + Jitter C2 Rules      █
██████████████████████████████████████████████████████████████████████████████████████

+-----------------------+-------------------------------+-------------------------------+-----+
|        TACTIC         |         TECHNIQUE ID          |          TECHNIQUE NAME       | HIT |
+-----------------------+-------------------------------+-------------------------------+-----+
| Initial Access        | T1189                         | Drive-by Compromise           |     |
|                       | T1190                         | Exploit Public-Facing App     |     |
+-----------------------+-------------------------------+-------------------------------+-----+
| Execution             | T1059.001                     | PowerShell                    | AMSI|
|                       | T1218                         | Signed Binary Proxy Execution | LOLB|
|                       | T1047                         | WMI Execution                 | LOLB|
+-----------------------+-------------------------------+-------------------------------+-----+
| Persistence           | T1547                         | Boot/Logon Autostart Exec     | LOLB|
|                       | T1543.003                     | Create/Modify Windows Service | C2  |
+-----------------------+-------------------------------+-------------------------------+-----+
| Privilege Escalation  | T1055                         | Process Injection             | AMSI|
|                       | T1548                         | Abuse Elevation Control       |     |
+-----------------------+-------------------------------+-------------------------------+-----+
| Defense Evasion       | T1562.001                     | Disable Security Tools        | AMSI|
|                       | T1562.004                     | Disable/Modify Sys Config     | AMSI|
|                       | T1112                         | Modify Registry               | LOLB|
|                       | T1027                         | Obfuscated/Encoded Commands   | AMSI|
|                       | T1089                         | Disabling Security Products   | AMSI|
+-----------------------+-------------------------------+-------------------------------+-----+
| Credential Access     | T1003.001                     | LSASS Memory Dumping          | AMSI|
|                       | T1558.003                     | Kerberos Attacks              |     |
+-----------------------+-------------------------------+-------------------------------+-----+
| Discovery             | T1083                         | File and Dir Discovery        |     |
|                       | T1012                         | Registry Query                |     |
+-----------------------+-------------------------------+-------------------------------+-----+
| Lateral Movement      | T1047                         | WMI                           | LOLB|
|                       | T1021.006                     | WinRM (5985/5986)             | C2  |
+-----------------------+-------------------------------+-------------------------------+-----+
| Collection            | T1056                         | Input Capture                 |     |
+-----------------------+-------------------------------+-------------------------------+-----+
| Command & Control     | T1071                         | Application Layer Protocol    | C2  |
|                       | T1573                         | Encrypted Channel             | C2  |
|                       | T1090                         | Proxy / Tunneling             | C2  |
|                       | T1008                         | Fallback Channels             | C2J |
|                       | T1105                         | Ingress Tool Transfer         | C2  |
+-----------------------+-------------------------------+-------------------------------+-----+
| Exfiltration          | T1041                         | Exfil Over C2 Channel         | C2J |
|                       | T1020                         | Automated Exfiltration        | C2J |
+-----------------------+-------------------------------+-------------------------------+-----+
| Impact                | T1489                         | Service Stop                  | AMSI|
+-----------------------+-------------------------------+-------------------------------+-----+
 ────────────────────────────────────────────────────────────────────────────────────────
 █ AMSI  = AMSI / LOLBins Defense Evasion Rule Coverage
 █ LOLB  = LOLBin Abuse Detection (mshta, rundll32, regsvr32, wmic, certutil, bitsadmin)
 █ C2    = Suspicious Ports Static Detector
 █ C2J   = Hybrid Jitter C2 Detector (interval drift + periodicity scoring)
──────────────────────────────────────────────────────────────────────────────────────────
~~~


