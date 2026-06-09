Markdown
# 🗺️ Minimum Truth Detection Framework (MTDF) — God Mode Composite Roadmap
Copyright (c) 2026 Ala Dabat. All Rights Reserved.  
Licensed under CC BY-NC-SA 4.0 (Attribution-NonCommercial-ShareAlike)

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
