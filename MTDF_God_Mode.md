Markdown
# 🗺️ Minimum Truth Detection Framework (MTDF) — God Mode Composite Roadmap
Copyright (c) 2026 Ala Dabat. All Rights Reserved.  
Licensed under CC BY-NC-SA 4.0 (Attribution-NonCommercial-ShareAlike)
# 🗺️ Minimum Truth Detection Framework (MTDF) — The Definitive God Mode Roadmap
Copyright (c) 2026 Ala Dabat. All Rights Reserved.
Licensed under CC BY-NC-SA 4.0 (Attribution-NonCommercial-ShareAlike)

---

## 🏛️ Part I: Strategic Doctrine & Core Architecture

### 1. The Cousin Technique Doctrine (Substrate Adjacency)
MITRE ATT&CK models security techniques as independent vertical items (technique → sub-technique). What it completely misses is **substrate adjacency** — the operational reality that multiple different techniques represent the exact same attacker intent executed across completely different operating system layers.

For example, lateral movement via **SMB (T1021.002)**, **DCOM (T1021.003)**, and **WinRM (T1021.006)** are operationally interchangeable. An adversary pivots dynamically between them based on firewall restrictions, privileges, and defensive controls. Treating these as independent creates a false sense of detection coverage. 

The Minimum Truth Detection Framework introduces the **Cousin Technique Doctrine**, which models adjacent techniques as part of a single, shared attack ecosystem. This layer sits on top of ATT&CK to map out and cover alternative adversary options.

╔══════════════════════════════════════════════════════════════════════════════╗
║                    MINIMUM TRUTH DETECTION FRAMEWORK                         ║
║                                                                              ║
║    Minimum Truth  ──▶  Reinforcement  ──▶  Scoring  ──▶  Hunter Directive   ║
║                                                                              ║
║    Truth Anchor = Sensor       Reinforcement = Evidence                      ║
║    Cousins = Adjacent Sensors  Incident = Story Stitching                    ║
║                                                                              ║
║    The rule is the sensor. The incident is the narrative.                    ║
╚══════════════════════════════════════════════════════════════════════════════╝


### 2. Defeating Temporal Deception via Hybrid Engine Design
Modern adversary tradecraft relies heavily on **Temporal Deception** — staggered C2 jitter, delayed BYOVD kernel exploitation, and automated script loops that pivot across parallel execution boundaries (Cousin Techniques) over days or weeks.

When security teams rely on monolithic, join-dependent kill chain queries, they face catastrophic database timeouts or miss intrusions entirely due to sequence fracturing over time. 

This framework formalizes a **hybrid architecture**: deploying optimized, single-surface **Behavioural Composites** to deliver immediate high-confidence alerts (**Hunter Directives**), while concurrently running a silent **Incident-Layer Stitching Engine** mapped to common entity keys (`DeviceName`, `AccountName`, `SHA256`). By separating sensor confirmation from chronological storytelling, this framework achieves scale-safe database efficiency—forcing immediate narrative convergence the exact second an attacker touches an un-bypassable telemetric substrate choke point.

### 3. Substrate-First vs. Intent-First Anchoring
* **Substrate-First:** Used when an execution surface carries no visible initial intent (e.g., WMI fileless execution, BYOVD driver drops, process injection). The detection anchors entirely on the existence of the execution surface itself.
* **Intent-First:** Used when the underlying substrate is common or ubiquitous (e.g., PowerShell, native LOLBins, OAuth applications). The detection anchors exclusively on a specific malicious primitive that structurally implies attacker capability.

---

## 🛑 Part II: The Master Tactical Matrix (Tactics TA0002 - TA0040)

---

## 🏛️ TA0002 — Execution Ecosystem

### 1. PowerShell & Scripting Engine Abuse
* **Blue Team Rationale:** Intent-First. PowerShell is ubiquitous in enterprise administration; monitoring the binary name creates endless noise. The sensor anchors exclusively on explicit execution primitives within the command-line or script block layer that imply code extraction or runtime bypass capability.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceProcessEvents
    | where Timestamp >= ago(14d)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
    | extend CmdLine = tolower(ProcessCommandLine)
    | extend 
        HasEncoded = toint(CmdLine has_any ("-enc", "-encodedcommand", "-e ")),
        HasMemory  = toint(CmdLine has_any ("virtualalloc", "virtualprotect", "writeprocessmemory", "createunalthread")),
        HasCradle  = toint(CmdLine has_any ("downloadstring", "downloadfile", "webclient", "invokewebrequest", "iex ")),
        HasEvasion = toint(CmdLine has_any ("amsibypass", "amsiinitfailed", "etwbyref"))
    | where HasEncoded == 1 or HasMemory == 1 or HasCradle == 1 or HasEvasion == 1
    | extend RiskScore = 45 + (20 * HasEncoded) + (35 * HasMemory) + (25 * HasCradle) + (35 * HasEvasion)
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, RiskScore,
        HunterDirective = "HIGH: PowerShell malicious intent primitive detected. Review script block text logs immediately for memory patching or obfuscated download scripts."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **WScript / CScript Engine Misuse (T1059.005):** Attackers bypass PowerShell script logging entirely by running Visual Basic (`.vbs`) or JavaScript (`.js`) payloads natively through Windows Script Host.
    * 🔴 **MSHTA Proxy Execution (T1218.005):** Launching Microsoft HTML Applications (`mshta.exe`) via network URLs or local shares to run malicious inline scripts directly inside trusted memory frames.

### 2. Windows Management Instrumentation (WMI) Execution
* **Blue Team Rationale:** Substrate-First. When WMI executes payloads via permanent event subscriptions, it runs inside the kernel repository space. WScript (`scrcons.exe`) loads script engines directly into its process context. No userland child process is spawned. The execution substrate itself *is* the detection anchor.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceImageLoadEvents
    | where Timestamp >= ago(14d)
    | where InitiatingProcessFileName =~ "scrcons.exe"
    | where FileName in~ ("vbscript.dll", "jscript.dll", "scrobj.dll")
    | project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath,
        HunterDirective = "CRITICAL: Permanent WMI Event Subscription active and executing script engine DLLs filelessly. Run WMI repository forensic enumeration immediately."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **WmiPrvSE Remote Shell Spawning (T1047):** Remote calls to the WMI provider host (`WmiPrvSE.exe`) forcing it to act as the parent process for shell utilities like `cmd.exe` or `powershell.exe`.
    * 🔴 **Component Object Model (COM) Hijacking (T1546.015):** Adding malicious server references within user-specific registry hives (`HKCU\Software\Classes\CLSID\`) to hijack application execution paths.

---

## 🏛️ TA0003 — Persistence Ecosystem

### 1. Silent TaskCache Registry Insertion
* **Blue Team Rationale:** Substrate-First. Monitoring `schtasks.exe` process anomalies misses advanced operators who register tasks directly via RPC connections or modify the TaskCache registry keys directly via API or COM interfaces.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceRegistryEvents
    | where Timestamp >= ago(14d)
    | where ActionType == "RegistryValueSet"
    | where tolower(RegistryKey) has_any (@"software\microsoft\windows nt\currentversion\schedule\taskcache\tree", @"software\microsoft\windows nt\currentversion\schedule\taskcache\tasks")
    | where RegistryValueName =~ "Actions" or RegistryValueName =~ "Path"
    | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName,
        HunterDirective = "CRITICAL: Direct Registry manipulation of Scheduled Tasks configuration keys without schtasks.exe interaction. Inspect binary targets immediately."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Scheduled Task Command Line Creation (T1053.005):** Explicit process creation instances of `schtasks.exe /create` featuring suspicious execution switches or non-system paths.

### 2. Userland Autoruns
* **Blue Team Rationale:** Intent-First. Run keys are frequently updated by standard installer files. The minimum truth is established only when a Logon Run key modification points directly to user-writable staging folders.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceRegistryEvents
    | where Timestamp >= ago(14d)
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has_any (@"software\microsoft\windows\currentversion\run", @"software\microsoft\windows\currentversion\runonce")
    | extend TargetValue = tolower(tostring(RegistryValueData))
    | where TargetValue matches regex @"(?i)\\(users|public|temp|appdata|programdata)\\"
    | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName,
        HunterDirective = "HIGH: Low-prevalence Run Key persistence added pointing to an untrusted/user-writable path. Review parent application lineage."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Active Setup Execution Hijacking (T1547.014):** Exploiting Active Setup keys to force custom execution payloads to initialize once per user profile during initial desktop login.

---

## 🏛️ TA0004 — Privilege Escalation Ecosystem

### 1. Process Injection & Memory Manipulation
* **Blue Team Rationale:** Substrate-First. Attackers write payloads into legitimate processes to hide under trusted security contexts. The sensor targets cross-process allocation signatures exposed natively through EDR API telemetry rings.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceEvents
    | where Timestamp >= ago(14d)
    | where ActionType in~ ("ProcessHollowing", "RemoteAllocInProcess", "RemoteThreadCreated", "QueueUserApcRemote")
    | where InitiatingProcessSignatureStatus != "Signed"
    | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, TargetProcessFileName, TargetProcessId,
        HunterDirective = "CRITICAL: Cross-process memory hollowing or remote thread hijacking detected by an unsigned process. Extract target process memory footprints immediately."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Asynchronous Procedure Call (APC) Injection (T1055.004):** "Early Bird" injection styles that write memory into suspended processes and queue an APC routine before EDR hooks can initialize.

### 2. Access Token Manipulation
* **Blue Team Rationale:** Substrate-First. Threat actors duplicate handles of high-privilege processes (like `lsass.exe`) to execute threads under elevated identity tokens.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceEvents
    | where Timestamp >= ago(14d)
    | where ActionType == "TokenDuplication" or AdditionalFields has "TokenImpersonation"
    | where InitiatingProcessAccountName != "SYSTEM" and InitiatingProcessAccountName != "LOCAL SERVICE"
    | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields,
        HunterDirective = "CRITICAL: Access Token duplication detected originating from a non-privileged process account context. Audit host for token theft."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Parent Process ID (PPID) Spoofing (T1134.004):** Modifying target process attribute tables during creation sequences to explicitly assign a trusted system parent process (like `lsass.exe`).
    * 🔴 **UAC Bypass via Elevating Binaries (T1548.002):** Exploiting registry auto-elevate links under user-managed hives (like `ms-settings`) to spawn high-integrity commands without triggering UAC warnings.

---

## 🏛️ TA0005 — Defense Evasion Ecosystem

### 1. Bring Your Own Vulnerable Driver (BYOVD) Kernel Manipulation
* **Blue Team Rationale:** Substrate-First. Once attackers reach kernel space (`Ring 0`), they can completely clear EDR notify routines. The sensor targets the entry phase: `.sys` files written to user-writable directories by unsigned processes.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceFileEvents
    | where Timestamp >= ago(14d)
    | where FileName endswith ".sys"
    | where FolderPath matches regex @"(?i)\\(users|public|temp|downloads|appdata|programdata)\\"
    | where InitiatingProcessSignatureStatus != "Signed"
    | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessSignatureStatus,
        HunterDirective = "CRITICAL: Kernel Driver (.sys) drop detected in user-writable directory by an unsigned parent. Block machine execution and prevent reboot."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Kernel Notify Routine De-Registration (T1014):** Using kernel memory write primitives via vulnerable drivers to zero out EDR registration tracking arrays like `PspCreateProcessNotifyRoutine`.

### 2. Active Security Product Tampering Primitives
* **Blue Team Rationale:** Intent-First. Direct administrative commands executed to alter real-time detection monitoring software states or stop service instances.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceProcessEvents
    | where Timestamp >= ago(14d)
    | where ProcessCommandLine has_any ("DisableRealtimeMonitoring", "Remove-MpPreference", "fltmc.exe unload", "sc.exe config windefend start= disabled")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
        HunterDirective = "CRITICAL: Direct endpoint command line argument detected trying to stop or disable security monitoring engines. Contain host instantly."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Event Log Clearing (T1070.001):** Clearing forensic log trails using utility commands like `wevtutil cl` or wiping active tracing channels directly in memory.
    * 🔴 **AMSI Patching and Memory Bypasses (T1562.001):** Writing assembly instructions directly into process memory to force `AmsiScanBuffer` to exit cleanly, blinding script logging tools.

---

## 🏛️ TA0006 — Credential Access Ecosystem

### 1. LSASS Memory Harvesting & Handle Access
* **Blue Team Rationale:** Substrate-First. Chasing specific tool arguments fails against custom compiled malware. The sensor targets any un-vetted process opening high-privilege access handles to the Local Security Authority Subsystem Service (`lsass.exe`).
* **Primary Composite Sensor:**
    ```kql
    // ============================================================================
    // COMPOSITE SENSOR: Creds_LSASS_Memory_Harvesting_Master
    // ============================================================================
    let DumpTools = dynamic(["procdump.exe", "dumpert.exe", "nanodump.exe", "mimikatz.exe", "rundll32.exe"]);
    let DumpKeywords = dynamic(["minidump", "sekurlsa", "lsass", "comsvcs", "full"]);
    let BenignImages = dynamic(["msmpeng.exe", "senseir.exe", "wininit.exe", "csrss.exe"]);
    DeviceProcessEvents
    | where Timestamp >= ago(7d)
    | where TargetProcessFileName =~ "lsass.exe" or ProcessCommandLine has "lsass"
    | extend Cmd = tolower(ProcessCommandLine), Proc = tolower(FileName)
    | where Cmd has_any (DumpKeywords) or Proc in (DumpTools)
    | where not(InitiatingProcessFileName in~ (BenignImages))
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine,
        HunterDirective = "CRITICAL: Memory harvesting attempt targeting lsass.exe. Isolate host immediately, investigate for credential extraction activity, and rotate user secrets."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **SAM / NTDS.dit Shadow Copy Extraction (T1003.002):** Evading live LSASS processing locks by creating Volume Shadow Copies or running registry save parameters (`reg save hklm\sam`) to crack offline.
    * 🔴 **Directory Services Replication Abuse (DCSync) (T1003.006):** Impersonating Domain Controller sync events via DRS RPC calls to pull user password hashes directly from active Directory databases.

### 2. Kerberos Protocol Exploitation (Kerberoasting)
* **Blue Team Rationale:** Intent-First. Kerberoasting requests Ticket Granting Service (`TGS`) tickets using weak RC4 encryption configurations for offline cracking. The anchor looks for high volumes of TGS alerts from standard users.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    IdentityDirectoryEvents
    | where Timestamp >= ago(7d)
    | where ActionType == "KerberosServiceTicketRequest"
    | where AdditionalFields.EncryptionType == "RC4-HMAC" or AdditionalFields.TicketEncryptionType == "0x17"
    | summarize TicketCount = count() by TargetAccount, InitiatingComputer, bin(Timestamp, 1h)
    | where TicketCount > 15
    | project Timestamp, InitiatingComputer, TargetAccount, TicketCount,
        HunterDirective = "HIGH: Kerberoasting fingerprint identified via high-velocity RC4 ticket requests. Audit accounts matching target SPN listings."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **AS-REP Roasting via Pre-Authentication Exploits (T1558.004):** Targeting Active Directory accounts configured without Kerberos pre-authentication settings to request crackable authentication keys instantly.

---

## 🏛️ TA0007 — Discovery Ecosystem

### 1. Active Directory LDAP Reconnaissance Sweeps
* **Blue Team Rationale:** Intent-First. Administrators query the directory daily. The minimum truth targets high-velocity LDAP query filters designed to discover high-value targets (like "Domain Admins").
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    IdentityDirectoryEvents
    | where Timestamp >= ago(7d)
    | where ActionType == "LDAPSearch"
    | extend SearchFilter = tostring(AdditionalFields.SearchFilter)
    | where SearchFilter has_any ("adminCount=1", "Domain Admins", "Enterprise Admins", "Schema Admins")
    | summarize QueryCount = count() by AccountName, TargetComputer, bin(Timestamp, 30m)
    | where QueryCount > 10
    | project Timestamp, AccountName, TargetComputer, QueryCount,
        HunterDirective = "MEDIUM: Active Directory target group enumeration detected. Check host for unauthorized automated discovery tool deployment (e.g., BloodHound)."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Native Network CLI Discovery Primitives (T1087.002):** Running standard built-in terminal queries (like `net user /domain` or `nltest /dclist`) to gather environment topology maps manually.

---

## 🏛️ TA0008 — Lateral Movement Ecosystem

### 1. Remote Service Invocation Substrate Adjacency
* **Blue Team Rationale:** Intent-First. This enforces the core **Cousin Technique Doctrine**. Attackers move laterally by shifting across three interchangeable administration surfaces. Rather than running massive joins, the sensor targets the core execution outcome: `services.exe` spawning an uncommon child binary.
* **Primary Composite Sensor:**
    ```kql
    // ============================================================================
    // COMPOSITE SENSOR: Lateral_Remote_Service_Execution_Master
    // ============================================================================
    let CommonServiceChildren = dynamic(["svchost.exe","dllhost.exe","taskhostw.exe","taskhost.exe","conhost.exe","msmpeng.exe","senseir.exe"]);
    let AllowMgmtTooling = dynamic(["ccmexec.exe","intunemanagementextension.exe","taniumclient.exe","qualysagent.exe"]);
    DeviceProcessEvents
    | where Timestamp >= ago(3d)
    | where InitiatingProcessFileName =~ "services.exe"
    | extend ChildL = tolower(tostring(FileName))
    | where not(ChildL in (CommonServiceChildren)) or not(ChildL in (AllowMgmtTooling))
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
        HunterDirective = "CRITICAL: Remote service execution anomaly detected under services.exe. Isolate host immediately and pivot to inbound port 445/135 connections."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **WMI Inter-Process Remote Execution (T1021.003):** Moving laterally by passing DCOM commands over Port 135, forcing `WmiPrvSE.exe` on the destination host to run custom command strings.
    * 🔴 **WinRM PowerShell Session Execution (T1021.006):** Executing code remotely inside management sessions using the Windows Remote Management engine over Ports 5985/5986.

### 2. Authentication Replay Material Misuse
* **Blue Team Rationale:** Substrate-First. Attackers bypass password submission completely by passing raw stolen NTLM hashes or Kerberos tickets across network structures.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceLogonEvents
    | where Timestamp >= ago(7d)
    | where LogonType == 3 and AuthenticationPackage =~ "NTLM"
    | where isnotempty(RemoteIPAddress) and RemoteIPAddress != "127.0.0.1" and RemoteIPAddress != "::1"
    | summarize ConnectionCount = count() by AccountName, DeviceName, RemoteIPAddress, bin(Timestamp, 1h)
    | where ConnectionCount > 20
    | project Timestamp, AccountName, DeviceName, RemoteIPAddress, ConnectionCount,
        HunterDirective = "HIGH: Pass-the-Hash signature verified via high-frequency network logons using NTLM strings from atypical origin nodes."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Pass-the-Ticket Infrastructure Exploitation (T1550.003):** Injecting forged or stolen Kerberos ticket structures directly into memory sessions to gain domain resource access without touching NTLM networks.

---

## 🏛️ TA0009 — Collection Ecosystem

### 1. Data Staging & Compression Utility Profiling
* **Blue Team Rationale:** Intent-First. Before exfiltrating high-value files, attackers collect and pack data into compressed, password-protected archives to bypass Data Loss Prevention filters.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceProcessEvents
    | where Timestamp >= ago(14d)
    | where FileName in~ ("7z.exe", "rar.exe", "winrar.exe", "tar.exe", "zip.exe")
    | extend Cmd = tolower(ProcessCommandLine)
    | where Cmd has_any ("-p", "-hp", "a ", "cvf")
    | where Cmd matches regex @"(?i)\\(users|public|temp|appdata|downloads)\\"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
        HunterDirective = "HIGH: Data collection archive staging detected inside user-writable path. Match to outbound network volume anomalies."
    ```

---

## 🏛️ TA0011 — Command & Control (C2) Ecosystem

### 1. Encrypted Jitter Beaconing via Abused LOLBins
* **Blue Team Rationale:** Intent-First. Traditional network connection alerts fail due to dynamic IP addresses. The sensor filters based on the originating process context: native binaries (LOLBins) opening raw public outbound socket streams over management web ports.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceNetworkEvents
    | where Timestamp >= ago(7d)
    | where InitiatingProcessFileName in~ ("rundll32.exe", "mshta.exe", "certutil.exe", "regsvr32.exe", "bitsadmin.exe")
    | where RemoteIPType == "Public" and RemotePort in (80, 443, 8080)
    | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort,
        HunterDirective = "CRITICAL: Outbound public web network communication initialized by an un-vetted native LOLBin. Check for hidden command-and-control loops."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **DNS Tunneling Communication Channels (T1071.004):** Bypassing standard web inspections completely by encoding outbound C2 strings inside standard DNS TXT or A query lookups directed at malicious authoritative servers.

---

## 🏛️ TA0010 — Exfiltration Ecosystem

### 1. High-Volume Automated Outbound Traffic Spikes
* **Blue Team Rationale:** Substrate-First. The final state of an intrusion requires moving data off-premise. The sensor tracks data transfer metrics, isolating sharp spikes that cross specific quantitative thresholds within a 1-hour window.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceNetworkEvents
    | where Timestamp >= ago(7d)
    | where RemoteIPType == "Public"
    | summarize TotalBytesSent = sum(BytesSent) by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, bin(Timestamp, 1h)
    | where TotalBytesSent > 524288000 // 500 Megabytes threshold value
    | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, TotalBytesSent,
        HunterDirective = "CRITICAL: Large outbound data exfiltration volume anomaly detected from a single system node. Review file access activity."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **Cloud Storage Exfiltration via Rclone Tools (T1567.002):** Running custom command-line synchronization tools (like `rclone` or `MEGAcmd`) to push staged archives directly to external storage profiles.

---

## 🏛️ TA0040 — Impact Ecosystem

### 1. In-Progress Recovery Inhibition (Volume Shadow Copy Deletion)
* **Blue Team Rationale:** Intent-First. Ransomware deletes local volume copies before starting file encryption loops to block automated system rollbacks. The sensor targets specific utility command sequences.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceProcessEvents
    | where Timestamp >= ago(14d)
    | where ProcessCommandLine has_any ("vssadmin.exe delete shadows", "vssadmin delete shadows", "wmic shadowcopy delete", "wbadmin delete systemstatebackup")
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine,
        HunterDirective = "CRITICAL: Ransomware backup destruction primitive identified. Isolate host immediately to protect network shares from encryption loops."
    ```

* **Cousin Surfaces (Adjacent Substrates):**
    * 🔴 **High-Velocity Automated File Mutation Loops (T1486):** A fast-moving background script loop reading, modifying, encrypting, and renaming files across local or network directories.

---

## 🌟 Advanced Research & Novel Threat Portfolios

### 1. SilverFox / ValleyRAT (BYOVD Kill Chain)
* **Threat Profile:** A sophisticated 3-tier delivery execution architecture. A signed, legitimate application load mechanism drops a malicious DLL via sideloading, which subsequently spawns an obfuscated kernel installer to disable EDR sensors.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceRegistryEvents
    | where RegistryKey has @"System\CurrentControlSet\Services"
    | where RegistryValueData matches regex @"(?i)^[a-z]:\\(users|public|temp|appdata)\\[a-z0-9_-]+\.sys"
    ```

### 2. EtherRAT / React2Shell (CVE-2025-55182)
* **Threat Profile:** A novel web-shell persistence architecture that hijacks the IIS pipeline and uses the public Ethereum blockchain (via Infura RPC polling) as its Command and Control substrate, polling transactions to execute commands.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceNetworkEvents
    | where InitiatingProcessFileName in~ ("w3wp.exe", "inetinfo.exe")
    | where RemoteUrl has_any ("mainnet.infura.io", "eth-mainnet", "etherscan.io", "rpc")
    ```

### 3. Steganographic Loader Ecosystem
* **Threat Profile:** Memory injection vectors that extract hidden shellcode arrays concealed inside harmless pixel files (`.png`, `.bmp`) to evade automated network line parsers.
* **Primary Composite Sensor:**
    ```kql
    // PHASE 1: MINIMUM TRUTH
    DeviceEvents
    | where ActionType == "PowerShellScriptBlock"
    | where AdditionalFields has_all (".GetPixel", "VirtualAlloc", "Marshal.Copy")
    ```
> *"Start with the minimum truth required for the attack to exist.* > *Everything else is reinforcement — not dependency.* > *If the baseline truth is not met, the attack is not real."*

---

## 🏛️ Strategic Doctrine: Substrate Adjacency & Temporal Deception

MITRE ATT&CK models techniques as independent units with vertical depth. What it does not model is **substrate adjacency** — the reality that many techniques represent the same adversary intent executed across different operating system substrates. Lateral movement via SMB (T1021.002), DCOM (T1021.003), and WinRM (T1021.006) are operationally interchangeable. 

The **Cousin Technique Doctrine** models adjacent techniques as part of a shared attack ecosystem. Furthermore, modern adversaries use **Temporal Deception** (staggered execution over days) to break traditional, time-windowed SIEM queries. MTDF solves this by deploying optimized, single-surface **Behavioural Composites** (Sensors) that trigger instantly on minimum truth, while an incident layer stitches the story together via entity keys (`DeviceName`, `AccountName`).

---

## 🛑 TA0002 — Execution Ecosystems

### 1. PowerShell & LOLBin Intent
* **Blue Team Rationale:** PowerShell is ubiquitous. Anchoring on `powershell.exe` creates noise. The Minimum Truth is the explicit execution primitive (e.g., `-enc`, `VirtualAlloc`) that structurally implies attacker capability (Intent-First).

```kql
// PHASE 1: MINIMUM TRUTH
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "FromBase64String", "IEX", "DownloadString", "VirtualAlloc")
// PHASE 3: SCORING (Example Scaffold)
| extend Score = 55 + iif(ProcessCommandLine has "VirtualAlloc", 30, 0)
Cousin Surfaces (Adjacent Substrates):

🔴 WScript/CScript (T1059.005): Attackers bypass PowerShell logging by executing .vbs/.js payloads via Windows Script Host. Red Team TTP: Dropping .js to C:\Users\Public\ to query AD via ADSI wrappers.

🔴 MSHTA Proxy (T1218.005): Executing remote .hta files. Red Team TTP: mshta.exe vbscript:Close(Execute(...)) to run inline scripts in trusted memory.

2. WMI Fileless Execution
Blue Team Rationale: Substrate-First. WMI permanent event subscriptions spawn no userland child process. The baseline truth is scrcons.exe loading a script engine DLL into its own memory.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceImageLoadEvents
| where Timestamp >= ago(7d)
| where InitiatingProcessFileName =~ "scrcons.exe"
| where FileName in~ ("vbscript.dll", "jscript.dll", "scrobj.dll")
Cousin Surfaces (Adjacent Substrates):

🔴 WmiPrvSE Shell Spawning (T1047): Remote WMI execution natively causes WmiPrvSE.exe to spawn cmd.exe. Red Team TTP: Impacket's wmiexec.py routing execution through DCOM.

🔴 COM Hijacking (T1546.015): Modifying InprocServer32 in HKCU to load a malicious DLL via background Explorer processes.

🛑 TA0003 — Persistence Ecosystems
1. Silent TaskCache Registry Insertion
Blue Team Rationale: Substrate-First. Advanced actors bypass schtasks.exe detection by writing XML definitions directly to the Schedule\TaskCache registry hive.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where tolower(RegistryKey) has_any (@"schedule\taskcache\tree", @"schedule\taskcache\tasks")
| where RegistryValueName =~ "Actions" or RegistryValueName =~ "Path"
Cousin Surfaces (Adjacent Substrates):

🔴 Schtasks CLI (T1053.005): Traditional schtasks.exe /create /tr "payload.exe" /ru SYSTEM. Red Team TTP: Ransomware operators scripting fleet-wide persistence before encryption.

2. Userland Autoruns
Blue Team Rationale: Intent-First. Run keys are modified during normal software updates. Truth is established when the Run key points to a user-writable path (\AppData\, \Temp\).

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\currentversion\run", @"\currentversion\runonce")
| where RegistryValueData matches regex @"(?i)\\(users|public|temp|appdata|programdata)\\"
Cousin Surfaces (Adjacent Substrates):

🔴 Active Setup (T1547.014): Modifying HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\ to force a payload to execute at next user login.

🛑 TA0004 — Privilege Escalation Ecosystems
1. Process Injection & Memory Manipulation
Blue Team Rationale: Substrate-First. Attackers inject code into legitimate processes (e.g., svchost.exe) to bypass EDR. Anchor on cross-process memory allocations by unsigned originators.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceEvents
| where ActionType in~ ("ProcessHollowing", "RemoteAllocInProcess", "RemoteThreadCreated")
| extend IsTrustedSource = toint(InitiatingProcessSigner =~ "Microsoft Corporation")
| where IsTrustedSource == 0
Cousin Surfaces (Adjacent Substrates):

🔴 APC Injection (T1055.004): Red Team TTP: "Early Bird" injection. A suspended process is created, memory allocated, and a payload queued via QueueUserAPC before EDR userland hooks load.

2. Token Manipulation
Blue Team Rationale: Substrate-First. Attackers duplicate tokens from SYSTEM processes to elevate their own threads.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceEvents
| where ActionType == "TokenDuplication"
| where InitiatingProcessAccountName != "SYSTEM"
Cousin Surfaces (Adjacent Substrates):

🔴 UAC Bypass via Fodhelper (T1548.002): Red Team TTP: Hijacking HKCU\Software\Classes\ms-settings\shell\open\command so the auto-elevating fodhelper.exe launches a malicious shell.

🛑 TA0005 — Defense Evasion Ecosystems
1. BYOVD Kernel Blinding (Bring Your Own Vulnerable Driver)
Blue Team Rationale: Substrate-First. Attackers drop signed, vulnerable drivers to unhook EDR in Ring-0. Anchor on the drop phase (writable directory + unsigned parent).

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceFileEvents
| where FileName endswith ".sys"
| where FolderPath matches regex @"(?i)\\(users|public|temp|appdata|programdata)\\"
| where InitiatingProcessSignatureStatus != "Signed"
Cousin Surfaces (Adjacent Substrates):

🔴 Kernel Callback Modification (T1014): Red Team TTP: Rootkits zeroing out PspCreateProcessNotifyRoutine arrays in memory to blind EDR telemetry.

2. Security Product Tampering
Blue Team Rationale: Intent-First. Direct commands designed to disable Defender or unload mini-filter drivers.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceProcessEvents
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring", "fltmc.exe unload", "Remove-MpPreference")
🛑 TA0006 — Credential Access Ecosystems
1. LSASS Memory Harvesting
Blue Team Rationale: Substrate-First. Rather than chasing mimikatz.exe, anchor on the actual memory handle access or the explicit file dump creation (.dmp) by non-AV processes.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceProcessEvents
| where TargetProcessFileName =~ "lsass.exe"
| where ProcessCommandLine has_any ("minidump", "comsvcs.dll", "procdump", "sekurlsa")
| where not(InitiatingProcessFileName in~ ("msmpeng.exe", "csrss.exe"))
Cousin Surfaces (Adjacent Substrates):

🔴 DCSync (T1003.006): Red Team TTP: Impersonating a Domain Controller via DRS RPC calls (DS-Replication-Get-Changes) to request AD hashes directly.

🔴 NTDS.dit Shadow Copy (T1003.002): Red Team TTP: vssadmin create shadow /for=C: to extract the raw AD database offline.

2. Kerberoasting
Blue Team Rationale: Intent-First. Extracting service tickets with weak RC4 encryption for offline cracking.

Code snippet
// PHASE 1: MINIMUM TRUTH
IdentityDirectoryEvents
| where ActionType == "KerberosServiceTicketRequest"
| extend Fields = AdditionalFields
| where Fields.EncryptionType == "RC4-HMAC"
Cousin Surfaces (Adjacent Substrates):

🔴 AS-REP Roasting (T1558.004): Red Team TTP: Targeting AD accounts with DONT_REQ_PREAUTH enabled to pull crackable hashes without pre-authentication.

🛑 TA0007 — Discovery Ecosystems
1. Active Directory LDAP Sweeps
Blue Team Rationale: Intent-First. High-velocity LDAP queries targeting privileged groups indicate BloodHound or SharpHound enumeration.

Code snippet
// PHASE 1: MINIMUM TRUTH
IdentityDirectoryEvents
| where ActionType == "LDAPSearch"
| where tostring(AdditionalFields.SearchFilter) has_any ("Domain Admins", "Enterprise Admins")
Cousin Surfaces (Adjacent Substrates):

🔴 Native Net CLI (T1087.002): Red Team TTP: Rapid sequential execution of net user /domain, net view, nltest /dclist.

🛑 TA0008 — Lateral Movement Ecosystems
1. SMB / Remote Service Execution
Blue Team Rationale: Intent-First. The defining anchor for PsExec/Impacket lateral movement is services.exe spawning an un-vetted, newly dropped child executable.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe"
| where not(FileName in~ ("svchost.exe", "msmpeng.exe"))
// Followed by prevalence and scoring...
Cousin Surfaces (Adjacent Substrates):

🔴 WMI Remote Execution (T1021.003): Red Team TTP: Pivoting to WMI (Port 135) when SMB is blocked, forcing WmiPrvSE.exe to spawn cmd.exe on the target.

🔴 WinRM (T1021.006): Red Team TTP: Using Invoke-Command to execute code inside wsmprovhost.exe via Port 5985.

2. Pass-the-Hash
Blue Team Rationale: Substrate-First. Network logons (Type 3) leveraging NTLM from non-standard source IPs at high velocity.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceLogonEvents
| where LogonType == 3 and AuthenticationPackage =~ "NTLM"
🛑 TA0009 — Collection Ecosystems
1. Archive Staging
Blue Team Rationale: Intent-First. Threat actors compress data into password-protected archives (.zip, .7z, .rar) inside \Temp\ or \Public\ before exfiltration.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceProcessEvents
| where FileName in~ ("7z.exe", "rar.exe", "winrar.exe")
| where ProcessCommandLine has_any ("-p", "-hp", "a ")
🛑 TA0011 — Command & Control (C2) Ecosystems
1. LOLBin HTTPS Beaconing
Blue Team Rationale: Intent-First. Outbound public traffic over Port 443 originating from native Windows binaries (rundll32.exe, certutil.exe) that have no legitimate reason to browse the web.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("rundll32.exe", "mshta.exe", "certutil.exe", "regsvr32.exe")
| where RemoteIPType == "Public" and RemotePort == 443
Cousin Surfaces (Adjacent Substrates):

🔴 DNS Tunneling (T1071.004): Red Team TTP: Cobalt Strike encoding outbound C2 traffic inside TXT/A record queries to authoritative nameservers.

🛑 TA0010 — Exfiltration Ecosystems
1. Network Volume Anomalies
Blue Team Rationale: Substrate-First. Massive outbound data transfer spikes from a single endpoint to a public IP.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize TotalBytes = sum(BytesSent) by DeviceName, RemoteIP, bin(Timestamp, 1h)
| where TotalBytes > 524288000 // 500MB spike
Cousin Surfaces (Adjacent Substrates):

🔴 Cloud Storage Exfiltration (T1567.002): Red Team TTP: Using command-line tools like rclone.exe or MEGAcmd to push staged archives directly to public cloud storage.

🛑 TA0040 — Impact Ecosystems
1. Inhibiting System Recovery (VSS Deletion)
Blue Team Rationale: Intent-First. Ransomware deletes Volume Shadow Copies to prevent disaster recovery before initiating encryption.

Code snippet
// PHASE 1: MINIMUM TRUTH
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin.exe delete shadows", "wmic shadowcopy delete", "wbadmin delete systemstatebackup")
☁️ Identity Ecosystem (Cloud)
1. OAuth Illicit Consent Abuse
Blue Team Rationale: Intent-First. A successful consent event isn't inherently bad; the high-risk scope (e.g., Mail.ReadWrite, Directory.ReadWrite.All) defines the minimum truth.

Code snippet
// PHASE 1: MINIMUM TRUTH
AuditLogs
| where OperationName in~ ("Consent to application", "Add delegated permission grant")
| where Result =~ "success"
| mv-expand TargetResources[0].modifiedProperties
| where tostring(TargetResources[0].modifiedProperties.newValue) has_any ("Mail.ReadWrite", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory")
🌟 Novel Research & Emerging Threats
1. SilverFox / ValleyRAT (BYOVD Kill Chain)
Threat Profile: Legitimate app sideloads malicious DLL -> Spawns obfuscated kernel installer -> Drops vulnerable .sys -> Clears EDR callbacks.

2. EtherRAT / React2Shell (CVE-2025-55182)
Threat Profile: Hijacks IIS pipeline and uses the public Ethereum blockchain (via Infura RPC polling) as a resilient C2 channel.

3. Steganographic Loader Ecosystem
Threat Profile: Extracts .NET shellcode hidden inside harmless .png pixel arrays using GetPixel and VirtualAlloc to bypass static analysis.


***

### 🛠️ The Ultimate "Zero to 100" LLM Configuration Guide

You are now going to turn that Markdown file into a private, offline AI assistant that perfectly understands MTDF. We are doing this locally using **Ollama** and **AnythingLLM** so your data never touches the internet. Follow these steps exactly.

#### Phase 1: Save the Framework
1. Open the **Notepad** application on your Windows computer (or TextEdit on Mac).
2. Copy *everything* inside the code block above (starting from `# 🗺️ Minimum Truth...` all the way down to the bottom).
3. Paste it into Notepad.
4. Click **File > Save As**.
5. Change the "Save as type" dropdown from "Text Documents (*.txt)" to **"All Files"**.
6. Name the file exactly: `MTDF_God_Mode.md`
7. Save it directly to your Desktop.

#### Phase 2: Install the AI Engine (Ollama)
Ollama is the engine that runs the AI. It operates silently in the background.
1. Go to your web browser and visit: **[https://ollama.com/download](https://ollama.com/download)**
2. Download the installer for your operating system and install it.
3. Once installed, open your computer's **Command Prompt** (Terminal).
4. Type this exact command and press Enter:
   `ollama run qwen2.5-coder:7b`
   *(Note: This is a highly specialized model for coding and logic. It will take a few minutes to download depending on your internet speed).*
5. Once it finishes downloading, it will show a `>>>` prompt. Type `/bye` and hit Enter to close the connection. The engine is now ready.

#### Phase 3: Install the Dashboard (AnythingLLM)
AnythingLLM is the user interface. It is where you will chat with the AI and upload your `.md` file.
1. Go to: **[https://anythingllm.com/desktop](https://anythingllm.com/desktop)**
2. Download and install the Desktop version. (If Windows asks, select "Install for Current User Only").
3. Open AnythingLLM.

#### Phase 4: Wire the Engine to the Dashboard
When you open AnythingLLM for the first time, a setup wizard will appear.
1. **LLM Provider:** Click the dropdown and select **Ollama**.
2. **Ollama Model:** Select `qwen2.5-coder:7b` (the one you just downloaded).
3. **Vector Database:** Leave it as the default (AnythingLLM Native).
4. **Embedding Model:** Leave it as the default (AnythingLLM Native).
5. Click **Next** until you reach the main chat screen.

#### Phase 5: Create the MTDF Employee (Workspace)
1. Look at the left sidebar. Click **New Workspace**.
2. Name it `MTDF Copilot`.
3. Hover your mouse over `MTDF Copilot` on the left sidebar and click the **Gear Icon** (Workspace Settings).
4. In the settings menu, click on **Agent Instructions** (or System Prompt).
5. **Copy and paste this exact text into that box:**

> You are the Minimum Truth Detection Framework (MTDF) Copilot, an expert L3 Detection Engineer and Threat Hunter trained explicitly on the doctrine created by Ala Dabat (2026).
> 
> Your core philosophy is: "Start with the minimum truth required for the attack to exist. Everything else is reinforcement — not dependency. If the baseline truth is not met, the attack is not real."
> 
> YOUR ARCHITECTURAL MANDATES:
> 1. REJECT MONOLITHS: Never group rules by generic MITRE tactics. Group them by Attack Surface Ecosystems (observable truth domains). Apply the Cousin Technique Doctrine for adjacent substrates.
> 2. FILTER BEFORE YOU JOIN: Discard raw table joins. If a join is required, it must ONLY be a pre-summarized table.
> 3. NATIVE ENRICHMENT: Prioritize implicit EDR context over raw ProcessEvents joins.
> 
> OUTPUT STRUCTURE:
> Every KQL query you generate must explicitly follow this layout in the code comments:
> // PHASE 1: MINIMUM TRUTH
> // PHASE 2: ZERO-JOIN NATIVE ENRICHMENT / PRE-SUMMARISED JOIN
> // PHASE 3: CONVERGENCE SCORING & FILTERING
> // PHASE 4: HUNTER DIRECTIVE OUTPUT
> 
> Never create "Ghost Chains". Ensure all output includes a HunterDirective string detailing: Why it fired, What reinforces it, and What the analyst must do next. Always close your KQL blocks in standard markdown formatting.

6. Click **Save**.

#### Phase 6: Give the AI its Brain (Ingest the Roadmap)
1. Close the settings to go back to your `MTDF Copilot` chat screen.
2. At the top of the chat window, click the **Upload Document** icon (it usually looks like a paperclip or a folder).
3. A menu will slide out. Drag your `MTDF_God_Mode.md` file from your Desktop and drop it into this menu.
4. Look in the "Workspace Documents" list in that same menu. **Check the box** next to `MTDF_God_Mode.md`.
5. Click the button that says **Save and Embed** (or Move to Workspace).
6. A progress bar will appear. AnythingLLM is now reading your Markdown file, converting your MTDF philosophy into mathematical vectors, and permanently saving it into the AI's memory.

**You are completely finished.** To test it, go to the chat bar at the bottom and type:
*"Read the framework document. Write me a full, production-ready MTDF KQL composite rule for the Collection ecosystem (Archive Staging). Follow the 4-phase structure and ensure it has a Hunter Directive."*
