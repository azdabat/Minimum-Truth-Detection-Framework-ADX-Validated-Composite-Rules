# Threat Hunting vs Detection Engineering
## A Methodological Framework — PEAK · TAHITI · Minimum Truth Integration
### Ala Dabat | azdabat | Minimum Truth Detection Framework

---

> *"A hunt is a question. A rule is a settled answer. Know which you're writing before you open your editor."*

---

## 01 · The Core Distinction

These are two fundamentally different disciplines that feed each other. Conflating them produces rules that are too broad to be useful in production, and hunts that are too narrow to find anything new.

| Dimension | Threat Hunting | Detection Engineering |
|---|---|---|
| **Mode** | Exploratory, hypothesis-driven | Codified, alert-generating |
| **Output** | Findings, pivot leads, validated patterns | Deployed rules with tuned thresholds |
| **Time window** | Broad — days, weeks, months | Continuous — real-time |
| **False positive tolerance** | High — analyst triages manually | Low — every alert costs analyst time |
| **Who runs it** | Analyst with domain expertise | Automated SIEM/XDR pipeline |
| **What it produces** | Hypotheses → validated IOAs | Composites → production alerts |
| **Tuning loop** | Fast iteration, pivot freely | Structured gate before promotion |
| **Framework role** | Discovers minimum truth | Codifies minimum truth |

The pipeline flows in one direction:

```
HUNT → VALIDATE → ENGINEER → COMPOSITE → PRODUCTION → HUNT (feedback)
```

The feedback loop closes when production rules surface new anomalies that inspire new hunt hypotheses. Neither discipline exists in isolation.

---

## 02 · When to Hunt vs When to Engineer

The decision is not about rule complexity — it is about **confidence in the pattern**.

```mermaid
flowchart TD
    A("New threat intelligence\\nor anomaly observed") --> B{"Is the attack pattern\\nwell-documented with\\nreliable behavioural anchors?"}
    B -->|Yes, with ADX validation| C["Detection Engineering\\nWrite composite rule\\nwith defined thresholds"]
    B -->|Partially understood| D["Threat Hunt\\nBroad hypothesis\\nwith open time window"]
    B -->|Novel / unknown| E["Research Hunt\\nFirst principles\\nno assumptions"]
    D --> F{"Hunt produced\\nvalidated TP patterns?"}
    F -->|Yes, ≥3 consistent TPs| G["Promote to Engineering\\nExtract minimum truth anchor\\nBegin composite build"]
    F -->|Inconclusive| H["Refine hypothesis\\nbroaden substrate scope\\nre-hunt"]
    E --> F
    G --> C
    C --> I["ADX Validation\\nEmpire telemetry test\\nFP/TP ratio gate"]
    I -->|Pass| J["Production Composite\\n+ Badge Assignment"]
    I -->|Fail — high FP| K["Back to hunt phase\\nNarrow the anchor"]
    style C fill:#04260f,stroke:#238636,color:#56d364
    style D fill:#0d2244,stroke:#1f6feb,color:#79c0ff
    style E fill:#21033f,stroke:#7B2FBE,color:#d2a8ff
    style J fill:#04260f,stroke:#238636,color:#56d364
```

### The three entry points:

**1. Known threat, documented technique** → Write the rule. You know what you're looking for. Start with the minimum truth anchor and build the composite. Hunt phase is already implicit in the prior research.

**2. Observed anomaly, unclear pattern** → Hunt first. Broad KQL, wide time window, manual triage. Extract the consistent behavioural anchor from confirmed TPs. Then engineer.

**3. Novel/emerging threat** → Research hunt. No prior behavioural model. Build the kill chain hypothesis from first principles (actor TTPs, malware analysis, vendor reporting). Validate in ADX. Then engineer if pattern holds.

---

## 03 · PEAK Methodology Applied to MTF

PEAK (**P**repare, **E**xecute, **A**ct) is the structural lifecycle for organised threat hunting. Applied to MTF:

```mermaid
flowchart LR
    P("PREPARE\\n────────\\nScope the hunt\\nIdentify data sources\\nBuild hypothesis\\nMap to MITRE ATT&CK\\nDefine success criteria") --> E
    E("EXECUTE\\n────────\\nBroad KQL queries\\nMultiple substrates\\nEntity-keyed baselining\\nTime window: 30-90 days\\nDocument every pivot") --> A
    A("ACT\\n────────\\nDocument TP/FP findings\\nExtract minimum truth\\nRaise incidents (if live)\\nDecide: engineer or re-hunt\\nUpdate framework gaps")
    A -->|Pattern validated| DE("DETECTION ENGINEERING\\nComposite build\\nADX test\\nBadge assignment\\nProduction deploy")
    A -->|Pattern inconclusive| P
    style P fill:#0d2244,stroke:#1f6feb,color:#79c0ff
    style E fill:#21033f,stroke:#7B2FBE,color:#d2a8ff
    style A fill:#2d1f00,stroke:#d29922,color:#e3b341
    style DE fill:#04260f,stroke:#238636,color:#56d364
```

### PEAK applied to a real scenario — hunting for WantToCry-style network share encryption:

**PREPARE:**
- Hypothesis: *"An attacker may be encrypting files via SMB writes from a single remote host, evading local process monitoring"*
- Data source: `DeviceNetworkEvents`, `FileEvents` where remote write origin is logged
- MITRE: T1486, T1570
- Success criteria: Identify 3+ hosts showing mass SMB write velocity with uniform extension change from a single source IP

**EXECUTE:**
```kql
// Broad hunt — look for mass file rename via network path
DeviceFileEvents
| where Timestamp > ago(90d)
| where ActionType in ("FileRenamed","FileCreated")
| where FolderPath startswith "\\\\"  // network path
| summarize FileCount = count(), 
            Extensions = make_set(tolower(tostring(split(FileName,".")[-1])))
  by DeviceName, InitiatingProcessRemoteIP, bin(Timestamp, 1h)
| where FileCount > 500
| where array_length(Extensions) < 3  // uniformity check
```

**ACT:**
- If confirmed: extract the minimum truth anchor (SMB write velocity + extension uniformity from remote IP)
- Raise incident if live
- Promote to `SMB_NetworkShare_EncryptionVelocity` composite

---

## 04 · TAHITI Process Applied to MTF

TAHITI (**T**arget, **A**pproach, **H**unting, **I**dentify, **T**riage, **I**nvestigate) is the structured process model for individual hunt execution.

```mermaid
flowchart TD
    T("TARGET\\nWhat are we hunting?\\nActor · Technique · Artefact\\nEx: InvisibleFerret Cython binary\\naccessing browser credentials") --> A
    A("APPROACH\\nHow will we hunt?\\nData-driven: anomaly in telemetry\\nTTP-driven: known attack pattern\\nIntel-driven: IOC/IOA from report\\nMethod: entity-keyed KQL hunt") --> H
    H("HUNTING\\nExecute KQL queries\\nBroad then narrow\\nDocument every finding\\nNo premature conclusions") --> I
    I("IDENTIFY\\nAnomalies vs baseline\\nSeparate noise from signal\\nApply context: is this expected?\\nMark TP/FP candidates") --> Tr
    Tr("TRIAGE\\nConfirm TPs with analyst\\nValidate in ADX\\nCorrelate with other signals\\nDocument FP patterns") --> Inv
    Inv("INVESTIGATE\\nDeep dive on confirmed hits\\nBuild full kill chain\\nExtract minimum truth anchor\\nDecide promotion path")
    Inv --> Done
    Done{"Consistent\\nbehavioural anchor\\nwith low FP rate?"}
    Done -->|Yes| Eng("Promote to Detection Engineering\\nComposite + badge assignment")
    Done -->|No| Back("Back to TARGET phase\\nRefine scope/approach")
    style T fill:#1a0a2e,stroke:#7B2FBE,color:#c9a0dc
    style H fill:#0d2244,stroke:#1f6feb,color:#79c0ff
    style Tr fill:#2d1f00,stroke:#d29922,color:#e3b341
    style Eng fill:#04260f,stroke:#238636,color:#56d364
```

### TAHITI applied — hunting InvisibleFerret (Void Dokkaebi):

| Phase | Applied Action |
|---|---|
| **Target** | Cython-compiled Python malware accessing browser credential stores; credential theft without Python script artefacts |
| **Approach** | Intel-driven: SOC Prime #022 + Void Dokkaebi research; anchor on credential store file access from non-browser processes |
| **Hunting** | KQL: DeviceFileEvents where FileName == "Login Data" AND InitiatingProcessFileName not in ("chrome.exe","msedge.exe","firefox.exe","brave.exe") |
| **Identify** | Flag processes accessing Login Data outside browser context; cross-reference with SetWindowsHookEx API calls (T1056.001) |
| **Triage** | Confirm: is this a backup tool, AV scan, or legitimate? Use process tree context, parent-child chain |
| **Investigate** | Confirmed non-browser access: extract process name, parent chain, network connections, loaded modules |

---

## 05 · The Hunt-to-Composite Pipeline

This is the formal gate system for promoting a hunt finding into a production composite rule. The MTF requires each rule to clear this pipeline before receiving a validated badge.

```mermaid
flowchart LR
    H1("Hunt Query\\nBroad · Exploratory\\nNo production threshold") --> V1
    V1("ADX Validation\\nRun against Empire telemetry\\nReal post-exploitation data\\nCount TPs vs FPs") --> G1
    G1{"FP rate\\nacceptable?"}
    G1 -->|High FP| N1("Narrow the anchor\\nAdd context conditions\\nEntity-keyed baseline\\nTime-window tightening")
    N1 --> V1
    G1 -->|Acceptable| C1("Composite Build\\nMinimum truth anchor +\\nCousin coverage map +\\nHunter Directive pack +\\nMITRE tagging")
    C1 --> B1("Badge Assignment\\nKQL ADX Validated ✅\\nPEAK/TAHITI Aligned 🏃\\nCousin Map documented 🔗\\nMDE/Sentinel tested 🛡")
    B1 --> P1("Production Deploy\\nIteration monitoring\\n30-day tuning window\\nFeedback → new hunts")
    style H1 fill:#21033f,stroke:#7B2FBE,color:#d2a8ff
    style C1 fill:#0d2244,stroke:#1f6feb,color:#79c0ff
    style B1 fill:#2d1f00,stroke:#d29922,color:#e3b341
    style P1 fill:#04260f,stroke:#238636,color:#56d364
```

### Promotion criteria:

| Criterion | Requirement |
|---|---|
| Minimum truth isolation | The anchor is the behaviour that must occur regardless of evasion method |
| ADX TP confirmation | ≥3 confirmed TPs on distinct attack scenarios |
| FP characterisation | Known FP patterns documented and filtered |
| Cousin map | Adjacent substrates mapped; gaps explicitly noted |
| Hunter Directive | Triage steps, pivot queries, and IR escalation path included |
| Dual platform | KQL tested against both MDE and Sentinel schemas |

---

## 06 · Badge Criteria — What Goes Where and Why

The six badges on the framework represent production quality gates. Here is the decision logic for each:

```mermaid
flowchart TD
    R("Rule exists") --> Q1{"Tested against live\\nEmpire ADX telemetry?"}
    Q1 -->|Yes, TP confirmed| ADX("✅ KQL ADX Validated\\nCore production badge")
    Q1 -->|No| ITER("🔄 Iteration — not yet\\nfor this badge")
    R --> Q2{"MITRE technique IDs\\nmapped with precision?"}
    Q2 -->|Yes, sub-technique level| MIT("MITRE ATT&CK Mapped")
    R --> Q3{"Cousin surfaces\\nexplicitly documented?"}
    Q3 -->|Yes, with gap notation| COU("Cousin Technique Doctrine")
    R --> Q4{"Hunt lifecycle\\ndocumented via\\nPEAK or TAHITI?"}
    Q4 -->|Yes, phases documented| PEAK_B("PEAK · TAHITI Aligned")
    R --> Q5{"Rule tested on both\\nMDE and Sentinel?"}
    Q5 -->|Both confirmed| PLAT("MDE · Sentinel")
    R --> Q6{"Original research\\nnot from vendor blogs?"}
    Q6 -->|Yes, novel tradecraft| NOV("Novel Tradecraft Research")
    style ADX fill:#04260f,stroke:#238636,color:#56d364
    style PEAK_B fill:#2d1f00,stroke:#d29922,color:#e3b341
    style NOV fill:#1a0a2e,stroke:#7B2FBE,color:#c9a0dc
```

### Badge assignment in practice:

**Most novel threats start at: `PEAK · TAHITI Aligned` + `MITRE ATT&CK Mapped`**

The reasoning:
- You've done the TAHITI process (Target, Approach, Hunt, Identify, Triage, Investigate)
- You've mapped to MITRE ATT&CK during the Target phase
- The rule is not yet ADX-validated (requires Empire telemetry test)
- The rule may not yet be dual-platform

Once the ADX test passes: add `✅ KQL ADX Validated`.
Once both MDE and Sentinel schemas are confirmed: add `MDE · Sentinel`.
Once cousin map is documented: add `Cousin Technique Doctrine`.
If original research: add `Novel Tradecraft Research`.

**The full badge set means the rule is production-grade.**

---

## 07 · Practical Hunt Playbooks

### Hunt 01 — LockBit Indicators Hunt

**Context:** LockBit uses a well-documented pre-encryption playbook. The hunt looks for the convergence of its preparation behaviours rather than any single IOC.

**TAHITI Target:** Pre-encryption preparation — privilege escalation, VSS deletion, service termination, and self-propagation via admin shares.

```mermaid
flowchart TD
    L1("Privilege Escalation\\nToken impersonation\\nT1134") --> L2
    L1b("Credential Dump\\nLSASS / NTDS\\nT1003") --> L2
    L2("Lateral Movement\\nSMB admin share propagation\\nT1021.002") --> L3
    L3("Defence Defeat\\nbcdedit /set recoveryenabled no\\nvssadmin delete shadows /all\\nT1490") --> L4
    L4("Service Termination\\nnet stop 'backup service'\\nStopping AV/EDR\\nT1489") --> L5
    L5("Encryption\\nLocalhost + Network shares\\nT1486") --> L6
    L6("Ransom Note\\nAll folders\\nT1491")
    style L3 fill:#2d1f00,stroke:#d29922,color:#e3b341
    style L5 fill:#3d0000,stroke:#da3633,color:#ff9ea0
```

**KQL Hunt — Pre-Encryption Convergence:**
```kql
let lookback = 30d;
let CandidateDevices =
    // Signal 1: VSS deletion attempt
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "vssadmin delete")
    | project DeviceName, VSSTime = Timestamp;

let ServiceKillDevices =
    // Signal 2: Backup/AV service termination
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where ProcessCommandLine has_any ("net stop", "sc stop")
       and ProcessCommandLine has_any ("vss","backup","sql","Exchange","DefWatch","ccEvtMgr","SavRoam","sqlserv","sqlagent","sqladhlp","Culserver","RTVscan","RANSOMWARE_DECOY")
    | project DeviceName, KillTime = Timestamp;

let BCDEditDevices =
    // Signal 3: Recovery disabled
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where ProcessCommandLine has_all ("bcdedit","/set") and ProcessCommandLine has "off"
    | project DeviceName, BCDTime = Timestamp;

// Convergence: devices showing all three signals within 24h
CandidateDevices
| join kind=inner ServiceKillDevices on DeviceName
| join kind=inner BCDEditDevices on DeviceName
| where abs(datetime_diff('hour', VSSTime, KillTime)) < 24
| where abs(datetime_diff('hour', VSSTime, BCDTime)) < 24
| project DeviceName, VSSTime, KillTime, BCDTime
| extend Alert = "⚠ PRE-ENCRYPTION CONVERGENCE — LockBit pattern"
```

**What this catches:** The pre-encryption preparation phase — the window before files are actually encrypted. This is the maximum-value detection point: the attacker has compromised the host but not yet destroyed data.

---

### Hunt 02 — Permission Exposure Hunt

**Context:** Overly permissive ACLs on sensitive paths are a pre-attack condition. This is an exposure hunt, not an active attack hunt — but it identifies the attack surface before it is exploited.

**TAHITI Target:** File system objects with Everyone/Authenticated Users write access in sensitive paths (system directories, credential stores, service binary paths).

```kql
// Hunt for writeable sensitive paths — permission exposure
// Note: Requires DeviceFileEvents + file permission data (Defender for Endpoint ATP)
let SensitivePaths = dynamic([
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\ProgramData\\Microsoft",
    "C:\\Windows\\SysWOW64"
]);

// Approach: look for file modifications in sensitive paths by non-elevated processes
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (SensitivePaths)
| where InitiatingProcessIntegrityLevel !in ("High", "System")  // non-elevated write
| where InitiatingProcessFileName !in ("MsMpEng.exe","svchost.exe","TiWorker.exe","wuauclt.exe")
| summarize WriteCount = count(), 
            Processes = make_set(InitiatingProcessFileName),
            SamplePaths = make_set(FolderPath, 5)
  by DeviceName, InitiatingProcessAccountName
| where WriteCount > 5
| extend Alert = "⚠ Non-elevated write to sensitive path"
| order by WriteCount desc
```

**Operational note:** This hunt complements but is distinct from the UAC bypass rule. The UAC bypass rule looks for registry manipulation to gain elevation; this hunt looks for the permission condition that would make a UAC bypass unnecessary.

---

### Hunt 03 — File Share Exposure Hunt

**Context:** Network shares with excessive access permissions are a lateral movement and data exfiltration pre-condition. This is the attack surface that WantToCry-style ransomware exploits.

**TAHITI Target:** Network shares accessible by Everyone, Domain Users, or Authenticated Users — particularly shares containing sensitive content.

```kql
// Hunt for anomalous access to network shares — potential exposure
// Covers both enumeration and high-volume access patterns
let lookback = 14d;

DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemotePort == 445  // SMB
| summarize
    ShareAccessCount = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    UniqueLocalPorts = dcount(LocalPort)
  by DeviceName, LocalIP
| where UniqueRemoteIPs > 20 or ShareAccessCount > 5000
| extend Alert = "⚠ Anomalous SMB share access volume — potential enumeration or exfil precursor"
| order by ShareAccessCount desc
```

**Hunting companion — find sensitive data in shares:**
```kql
// Look for access to files with sensitive naming patterns on network paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "\\\\"  // network path
| where FileName has_any (
    "password","passwd","credentials","creds","secret","private_key",
    "backup","database","salary","payroll","confidential"
)
| extend Extension = tostring(split(FileName,".")[-1])
| summarize FileCount = count(), 
            SensitiveFiles = make_set(FileName, 10),
            AccessingProcesses = make_set(InitiatingProcessFileName)
  by DeviceName, FolderPath
| order by FileCount desc
```

---

### Hunt 04 — Password File Exposure Hunt (password.xls and friends)

**Context:** Users storing passwords in plaintext files is a persistent credential exposure condition. Attackers with any foothold will hunt for these. This is a proactive hunt to find them first.

**TAHITI Target:** Files with names indicative of stored credentials — password.xls, credentials.txt, creds.csv, etc. — in user profile paths and shared directories.

```kql
// Hunt for password/credential files created or accessed
// Catches both the creation (misconfiguration) and the access (attacker hunting)
let lookback = 30d;

// Hunt 1: Find the files themselves
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName matches regex @"(?i)(password|passwd|creds?|credentials?|secret|login|vault|keystore|private[\-_]?key).*\.(xlsx?|csv|txt|doc[x]?|pdf|json|xml|ini|cfg|conf|kdbx)"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, 
          InitiatingProcessAccountName, InitiatingProcessCommandLine
| extend Alert = "⚠ Credential file created/modified — exposure risk"
| order by Timestamp desc

// Hunt 2: Find processes accessing these files (attacker hunting for them)
// Run as separate query
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileRead","FileAccessed")
| where FileName matches regex @"(?i)(password|passwd|cred|secret|login|vault).*\.(xlsx?|csv|txt|docx?)"
| where InitiatingProcessFileName !in ("EXCEL.EXE","WINWORD.EXE","notepad.exe","Code.exe","explorer.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| extend Alert = "⚠ Credential file accessed by non-standard process — potential harvesting"
| order by Timestamp desc
```

**What makes this a hunt (not a rule):** The file names are too variable for a reliable production rule with low FP. Hunt mode allows broad regex matching with manual triage. Once the environment's legitimate patterns are understood (backup scripts that open credentials.txt, etc.), a narrower production rule can be scoped.

**Promotion path:** After hunting and documenting FP patterns, `Credential_Keyword_Hunt` becomes the scoped production rule with documented FP exceptions.

---

### Hunt 05 — Novel Threat Onboarding (InvisibleFerret Pattern)

**Context:** When a novel threat emerges from intelligence reporting (e.g., SOC Prime newsletter, vendor blog, CERT-UA advisory), this is the standard onboarding workflow.

```mermaid
flowchart TD
    N1("Intelligence Received\\nSOC Prime #022:\\nInvisibleFerret — Cython .pyd\\ncredential theft + keylogging") --> N2
    N2("Kill Chain Mapping\\nMap to MITRE ATT&CK\\nT1555.003, T1056.001, T1115\\nIdentify all attack phases") --> N3
    N3("Substrate Analysis\\nWhat must the attacker do?\\nRegardless of compilation method:\\n→ Access browser credential store\\n→ Install keyboard hook\\n→ Monitor clipboard") --> N4
    N4("Minimum Truth Extraction\\nBrowser cred store access by non-browser process\\nSetWindowsHookEx from non-UI process\\nGetClipboardData burst from non-UI process") --> N5
    N5("Hunt Query Build\\nBroad KQL for each anchor\\nNo threshold yet\\n30-day lookback\\nMultiple substrates") --> N6
    N6("ADX Hunt Execution\\nRun against telemetry\\nDocument TPs, FPs, pivots") --> N7
    N7{"Pattern holds?\\n≥3 TPs, low FP?"}
    N7 -->|Yes| N8("Composite Build\\nMinimum truth + cousin map +\\nhunter directive + MITRE tag\\n→ Browser_CredStore_Access_Hunt")
    N7 -->|Inconclusive| N5
    N8 --> N9("Badge Assignment\\nPEAK/TAHITI Aligned ✅\\nMITRE Mapped ✅\\n→ ADX validation pending")
    style N4 fill:#0d2244,stroke:#1f6feb,color:#79c0ff
    style N8 fill:#04260f,stroke:#238636,color:#56d364
    style N9 fill:#2d1f00,stroke:#d29922,color:#e3b341
```

**Onboarding checklist for any novel threat:**

- [ ] Map attack phases to MITRE ATT&CK at sub-technique level
- [ ] Identify minimum truth anchor(s) — what must occur regardless of evasion
- [ ] Identify cousin substrates — same intent, different execution
- [ ] Write TAHITI documentation (Target → Investigate)
- [ ] Write broad hunt query (no threshold, 30-day lookback)
- [ ] Execute against ADX telemetry; document findings
- [ ] If ≥3 TPs: promote to composite with hunter directive
- [ ] Assign initial badges: MITRE Mapped + PEAK/TAHITI Aligned
- [ ] ADX validation: add KQL ADX Validated badge on pass
- [ ] Dual platform: add MDE · Sentinel badge on confirmation

---

## 08 · How the MTF Relates to PEAK and TAHITI

```mermaid
flowchart LR
    MTF("Minimum Truth\\nFramework\\n────────\\nMinimum truth anchor\\nCousin doctrine\\nComposite structure\\nHunter Directive")
    PEAK("PEAK\\n────────\\nPrepare\\nExecute\\nAct")
    TAHITI("TAHITI\\n────────\\nTarget\\nApproach\\nHunting\\nIdentify\\nTriage\\nInvestigate")
    MTF <-->|"Hunt lifecycle\\nstructure"| PEAK
    MTF <-->|"Individual hunt\\nprocess model"| TAHITI
    MTF -->|"What to hunt:\\nminimum truth anchors\\ncousin gaps"| PEAK
    TAHITI -->|"Findings feed\\ncomposite build"| MTF
    PEAK -->|"Act phase:\\npromotes to MTF\\ncomposite rule"| MTF
```

**The relationship in plain terms:**

- **PEAK** governs the *lifecycle* of a hunting engagement — the project-level view. Did we prepare properly? Did we execute with rigour? Did we act on findings?
- **TAHITI** governs the *process* of individual hunt execution — the analyst-level view. Do we have a clear target? Are we approaching it correctly? Have we investigated thoroughly?
- **MTF** governs the *content* of what gets produced — the engineering output. What is the minimum truth? What are the cousin surfaces? What is the composite structure?

You need all three. PEAK and TAHITI without MTF produce well-organised hunts that generate ad-hoc rules with no doctrine. MTF without PEAK/TAHITI produces well-structured rules with no systematic discovery process.

**The core of everything** is the minimum truth anchor. PEAK and TAHITI are the operational methodology for finding it. MTF is the doctrine for codifying and scaling it.

---

## 09 · The Minimum Truth Doctrine — Core of Everything

The framework's architectural insight is that **every detection must be anchored on behaviour that is invariant to evasion**. Not file hashes, not process names, not command-line strings that can be obfuscated — but the *action* that must occur.

```mermaid
flowchart TD
    A("Attacker Goal:\\nSteal browser credentials") --> B
    B("Evasion Attempts:") --> C1("Python script → Cython .pyd")
    B --> C2("Different process name")
    B --> C3("Different install path")
    B --> C4("Obfuscated code")
    C1 --> D("Minimum Truth Anchor:\\nSOME process must\\nopen Login Data SQLite\\nfrom outside browser context")
    C2 --> D
    C3 --> D
    C4 --> D
    D --> E("Detection fires\\nregardless of evasion method")
    style D fill:#0d2244,stroke:#1f6feb,color:#79c0ff
    style E fill:#04260f,stroke:#238636,color:#56d364
```

### The three questions for every rule:

1. **What is the minimum truth?** The single action that cannot be avoided. If the attacker doesn't do this, the attack doesn't work. This is your rule anchor.

2. **What are the cousin substrates?** The same attack intent executed on different surfaces. Map these explicitly. Every unmapped cousin is a free pivot for the attacker.

3. **What is the hunter directive?** When this rule fires, what does the analyst do? Where do they pivot? What confirms a TP vs FP? The rule is not complete without this.

---

## 10 · Rule Quality Rubric

Use this rubric before promoting any rule to production:

| Quality Check | Question | Pass Criteria |
|---|---|---|
| **Anchor clarity** | Can you state the minimum truth in one sentence? | Yes, clearly |
| **Evasion resistance** | Does the anchor hold if process name/hash/path is changed? | Yes — behaviour-first |
| **FP characterisation** | Do you know what legitimate activity looks like? | Documented FP exceptions |
| **Cousin coverage** | Are adjacent substrates mapped and gaps noted? | Cousin map present |
| **Dual-platform** | Does the KQL work in both MDE and Sentinel schemas? | Tested on both |
| **Hunter Directive** | Does the rule tell the analyst what to do next? | Steps documented |
| **ADX validation** | Has the rule fired on real adversary telemetry? | Empire test confirmed |
| **Temporal defeat** | If the attacker delays for 30 days, does the rule still fire? | Entity-keyed baseline |

---

*The framework is your doctrine. PEAK is your project lifecycle. TAHITI is your hunt process. The rules are the settled science — until the next threat forces a new hunt.*

---

**Repository:** github.com/azdabat | **Framework:** Minimum Truth Detection Framework  
**Author:** Ala Dabat | **Methodology alignment:** PEAK · TAHITI · MITRE ATT&CK  
**License:** CC BY-NC-SA 4.0
