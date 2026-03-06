# KQL Detection Engineering — Common Implementation Errors

**Author:** Ala Dabat  
**Framework:** Minimum Truth Detection Framework  
**Document Purpose:** Integration issues found during composite rule review (March 2026)  
**Rules Reviewed:** 11 composite detection rules across persistence, lateral movement, credential access, C2, and ingress transfer domains

---

## Overview

During systematic review of the Minimum Truth Detection Framework rule set, five recurring bug classes were identified across multiple rules. These are not random errors — they cluster around two root causes:

1. **Prevalence baseline design** — patterns built once and replicated without edge case hardening
2. **Multi-table join complexity** — sophisticated correlation architecture with implementation gaps in join semantics

None of these bugs invalidate the underlying detection logic. They are implementation issues in otherwise well-architected rules. This document exists so they are not repeated.

---

## Bug Class 1 — Prevalence Window Overlap

### Severity: HIGH

### Rules Affected
- `WMI-A2B_L2_Fileless_Consumer_Execution_Scrcons_Substrate`
- `Registry_Persistence_Background_Service_TaskCache`
- Any rule using a `RarityLB` or `OrgPrevalence` pattern

### Description

When building a rarity baseline (e.g. "how many days has this behaviour been seen on this device in the last 30 days"), the baseline window must **exclude** the active detection window. If both windows overlap, attack telemetry occurring during the detection period is included in the baseline calculation.

**Consequence:** An attacker operating for 2+ days within the detection window inflates `DeviceSeenDays` or `WriterDeviceCount`, suppressing the rarity flag (`IsRareOnDevice = 0`) on an **active intrusion**. The rule silently discounts the exact events it should be escalating.

### Broken Pattern

```kql
let lookback  = 7d;
let RarityLB  = 30d;

let R2_Prevalence =
DeviceImageLoadEvents
| where Timestamp >= ago(RarityLB)   // ← includes the 7d detection window
| summarize DeviceSeenDays = dcount(bin(Timestamp, 1d)) by DeviceId;
```

### Fixed Pattern

```kql
let R2_Prevalence =
DeviceImageLoadEvents
| where Timestamp >= ago(RarityLB) and Timestamp < ago(lookback)  // exclude detection window
| summarize DeviceSeenDays = dcount(bin(Timestamp, 1d)) by DeviceId;
```

### Rule of Thumb
> Prevalence baseline must end **before** the detection window begins. These two windows must never overlap.

---

## Bug Class 2 — Null SHA256 False Rarity

### Severity: HIGH

### Rules Affected
- `SMB_TaskExec_Svchost_Schedule_Empire_Cousin`
- `Registry_Persistence_Background_Service_TaskCache`
- Any rule using SHA256-based org prevalence for rarity scoring

### Description

When joining against an org prevalence table keyed on SHA256, processes that have no SHA256 populated (common for built-in Windows binaries such as `cmd.exe`, `powershell.exe`, `svchost.exe`) produce a null join result. After `coalesce(count, 0)`, the device count is 0, and the rarity condition `count <= 2` fires — marking common system binaries as **rare**.

**Consequence:** `powershell.exe`, `cmd.exe`, and other ubiquitous binaries receive a free rarity score boost on every alert, inflating `RiskScore` and producing false escalations.

### Broken Pattern

```kql
| join kind=leftouter (OrgPrevalence) on $left.ChildSHA == $right.SHA256
| extend ChildDeviceCount = coalesce(ChildDeviceCount, 0),
         ChildIsRare      = toint(ChildDeviceCount <= 2)  // ← fires on null SHA256
```

### Fixed Pattern

```kql
| join kind=leftouter (OrgPrevalence) on $left.ChildSHA == $right.SHA256
| extend ChildDeviceCount = coalesce(ChildDeviceCount, 0),
         ChildIsRare      = toint(isnotempty(ChildSHA) and ChildDeviceCount <= 2)
```

### Rule of Thumb
> Always guard rarity conditions with `isnotempty(SHA256)`. A null SHA256 is not evidence of rarity — it is evidence of missing telemetry.

---

## Bug Class 3 — `leftouter` Join Converted to Inner Join

### Severity: CRITICAL

### Rules Affected
- `Ingress_Tool_Transfer_Native_LOLBins`
- `SMB_TaskExec_Svchost_Schedule_Empire_Cousin` (partial)
- Any rule using `join kind=leftouter` followed by a `where` filter on right-side fields

### Description

A `leftouter` join preserves all rows from the left table, filling right-side fields with null when no match exists. However, if a `where` filter is applied **after** the join that references right-side fields, rows with null right-side values are silently dropped — converting the `leftouter` semantics to an effective `inner` join.

**Consequence:** Every base event that has **no matching reinforcement artifact** (no file drop, no network connection, no child process) is silently dropped from the result set. The rule only alerts when reinforcement is confirmed, making the baseline truth gate meaningless. Real attacks with no observed reinforcement are missed entirely.

### Broken Pattern

```kql
Base
| join kind=leftouter (FileArtifacts) on DeviceId
| where (WriterProcessId == ProcessId)          // ← drops all rows where FileArtifacts had no match
  and abs(datetime_diff("minute", Timestamp, FileTime)) <= NearWindowMins
```

### Fixed Pattern

```kql
Base
| join kind=leftouter (FileArtifacts) on DeviceId
| extend IsFileMatch = (
    WriterProcessId == ProcessId
    and abs(datetime_diff("minute", Timestamp, FileTime)) <= NearWindowMins
  )
| summarize
    FileNear     = max(toint(IsFileMatch)),
    DroppedFiles = make_set_if(DroppedFile, IsFileMatch, 10),
    arg_max(Timestamp, *)
  by DeviceId, ProcessId
```

### Rule of Thumb
> After a `leftouter` join, **never filter on right-side fields**. Always use `extend IsMatch` to flag matches, then aggregate. The `leftouter` must be allowed to produce null rows — that is its purpose.

---

## Bug Class 4 — `any()` Non-Determinism in Pass-Through Summarize

### Severity: MEDIUM–HIGH

### Rules Affected
- `Ingress_Tool_Transfer_PowerShell_Download_Cradle`
- `Ingress_Tool_Transfer_Native_LOLBins`
- Any rule using multiple `any()` calls to pass columns through a `summarize`

### Description

After a `leftouter` join produces a fan-out (one left row multiplied against multiple right rows), a `summarize` is used to collapse back to one row per entity. When individual columns are passed through using `any()`, KQL makes no guarantee about which source row each `any()` value comes from. Different columns in the same output row may originate from **different input rows**.

**Consequence:** The `Cmd` field (command line) may come from row A, while `HasExecIntent` (a flag derived from `Cmd`) comes from row B. The scoring flags and the evidence are inconsistent — an analyst reads a command line that does not explain the score, or a score that does not reflect the visible command.

### Broken Pattern

```kql
| summarize
    FileNear    = max(toint(IsFileMatch)),
    Timestamp   = max(Timestamp),
    Cmd         = any(Cmd),           // ← may come from a different row than HasExecIntent
    HasExecIntent = any(HasExecIntent)
  by DeviceId, ProcessId
```

### Fixed Pattern

```kql
| summarize
    FileNear     = max(toint(IsFileMatch)),
    DroppedFiles = make_set_if(DroppedFile, IsFileMatch, 10),
    arg_max(Timestamp, *)   // locks ALL other columns to the row with max Timestamp
  by DeviceId, ProcessId
```

### Rule of Thumb
> Replace all multi-column `any()` pass-through patterns with `arg_max(Timestamp, *)`. This locks every column to a single consistent source row, eliminating non-determinism.

---

## Bug Class 5 — Negative Score Floors

### Severity: LOW

### Rules Affected
- `C2_HTTPS_Jitter_BeaconShape_LowCPU`
- `C2_NamedPipe_IPC_SMB_ServiceConvergence`
- Any rule using penalty/suppression scoring modifiers

### Description

Rules using soft suppression (negative score modifiers for browsers, cloud agents, baseline accounts) can produce negative final scores when no positive conditions fire. The severity gate (`where Severity != "INFO"` or `where RiskLevel in (...)`) correctly suppresses these, but the negative scores still surface in raw output and pipeline consumers.

**Consequence:** Analysts reviewing raw results or downstream SIEM integrations parsing score fields encounter negative numbers, creating confusion about scoring semantics and eroding trust in the rule output.

### Broken Pattern

```kql
| extend BeaconScore =
      iif(AvgIntervalSec between (10 .. 3600), 20, 0)
    + iif(IsBrowserLike == 1, -15, 0)   // can drive total negative
    + iif(IsCommonCloud == 1, -10, 0)
// No floor — BeaconScore can be -25 in output
```

### Fixed Pattern

```kql
| extend BeaconScore =
      iif(AvgIntervalSec between (10 .. 3600), 20, 0)
    + iif(IsBrowserLike == 1, -15, 0)
    + iif(IsCommonCloud == 1, -10, 0)
| extend BeaconScore = iif(BeaconScore < 0, 0, BeaconScore)  // floor at 0
```

### Rule of Thumb
> Always floor composite scores at 0 after applying penalties. A score below zero has no semantic meaning in a risk-based alerting system.

---

## Quick Reference Checklist

Use this checklist when reviewing any rule before production deployment.

| # | Check | Pattern to Look For | Fix |
|---|-------|-------------------|-----|
| 1 | Prevalence window overlap | `ago(RarityLB)` with no upper bound | Add `and Timestamp < ago(lookback)` |
| 2 | Null SHA256 rarity | `coalesce(count, 0) <= 2` | Add `isnotempty(SHA256) and` before count check |
| 3 | leftouter → inner conversion | `join kind=leftouter` followed by `where` on right fields | Replace with `extend IsMatch` + `make_set_if` |
| 4 | `any()` non-determinism | Multiple `any(column)` in same summarize | Replace with `arg_max(Timestamp, *)` |
| 5 | Negative score floor | Penalty modifiers with no floor | Add `iif(score < 0, 0, score)` after scoring block |

---

## Additional Patterns Observed (Rule-Specific)

The following bugs were found in individual rules and are less likely to recur systematically, but are documented for completeness.

### Undefined Field References (Runtime Crash)
**Rule:** `COMPOSITE_L3_LSASS_CREDENTIAL_THEFT_MASTER`  
`HasHive = max(IsHive)` — field `IsHive` does not exist. Correct field is `IsHiveDump`. Query fails at runtime with column not found error. Always verify field names match exactly between definition and reference sites.

### Dead Code in Dynamic Lists
**Rule:** `COMPOSITE_L3_LSASS_CREDENTIAL_THEFT_MASTER`  
`comsvcs.dll` included in `DumpTools` list matched against `FileName` in `DeviceProcessEvents`. `FileName` is always a process executable — a DLL will never match. Dead code creates false sense of coverage.

### Dead Field Reference (Silent Miss)
**Rule:** `C2_NamedPipe_IPC_SMB_ServiceConvergence`  
`TargetProcessName` referenced in `DeviceEvents` query — field does not exist in MDE schema. Silently evaluates to null. Detection condition never fires for that branch.

### Regex Backslash Escaping
**Rule:** `C2_NamedPipe_IPC_SMB_ServiceConvergence`  
Named pipe regex used incorrect backslash escaping inside KQL raw strings. `ForkNRunHex` pattern never matched real pipe paths. Always validate regex patterns against sample telemetry in ADX before production.

### Bin Size / Correlation Window Boundary Miss
**Rule:** `SMB_Service_Execution_PsExec_Impacket`  
`BinSize = 5m` with `CorrWindow = 15m` — events 2 seconds apart across a bin boundary joined to different `BinTime` values and never correlated. Set `BinSize = CorrWindow` to guarantee adjacent event coverage.

### `substring()` Not Length-Safe
**Rules:** Multiple  
`substring(Cmd, 0, 240)` throws on strings shorter than 240 characters in some schema versions. Use:

```kql
substring(Cmd, 0, min(strlen(Cmd), 240))
```

### `base64_decode_string()` Not Guarded
**Rule:** `Registry_Persistence_Background_Service_TaskCache`  
`base64_decode_string("")` throws when `extract()` finds no match. Always guard:

```kql
iif(isnotempty(candidate), base64_decode_string(candidate), "")
```

### HunterDirective Defined After `project`
**Rule:** `Registry_Persistence_Background_Service_TaskCache`  
`extend HunterDirective` placed after `project` appends the column but excludes it from the explicit column list. Fragile — downstream `project` statements will drop it. Always define `HunterDirective` before `project` and include it explicitly.

---

## Framework Doctrine Reminder

These bugs do not affect the **detection doctrine** — the Minimum Truth anchors, convergence conditions, and reinforcement logic are architecturally sound across all rules reviewed. The issues are confined to:

- Baseline calculation scope
- Join semantics under multi-table correlation
- Score output formatting

The framework's core principle — *anchor on what must be true, reinforce with what raises confidence, suppress what is known good* — is correctly implemented. These are engineering hardening issues, not design failures.

---

*Document generated from systematic rule review session — March 2026*  
*Framework repository: github.com/azdabat*
