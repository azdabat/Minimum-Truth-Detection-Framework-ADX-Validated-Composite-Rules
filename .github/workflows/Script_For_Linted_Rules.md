# Lint & Fix: static checks for MTDF rules

Two scripts make up one workflow:

- **`lint_kql.py`** finds problems in composite KQL rules. It is **read-only**, which makes it safe to use as a CI gate.
- **`fix_kql.py`** rewrites the problems that are purely mechanical. It is the only tool that changes rule text, and by default it writes **corrected copies** without ever touching your originals.

Neither script runs KQL; both read rule text. Proof that a rule actually fires comes from [`run_tests.py`](run_tests.py) against real telemetry. The usual order is lint, then fix, then lint again, then test.

**Requirements:** Python 3.8+, no extra packages. Keep both files in the same folder, because `fix_kql.py` imports the parser from `lint_kql.py`.

---

## Quick start

Run from the repository root. In PowerShell, each command must be on a single line.

```powershell
# 1. Baseline: what's wrong today (writes nothing to your rules)
python tools\lint_kql.py "C:\path\to\rules" --no-port --md lint_report_before.md

# 2. Preview the mechanical fixes as a diff (writes nothing)
python tools\fix_kql.py "C:\path\to\rules" --dry-run --diff

# 3. Write corrected copies to fixed_rules\ and a change log to fix_report.md
python tools\fix_kql.py "C:\path\to\rules"

# 4. Lint the corrected copies: whatever is left needs a human
python tools\lint_kql.py fixed_rules --md lint_report_after.md
```

Comparing `lint_report_before.md` with `lint_report_after.md` gives you a measurable result: bugs found, bugs fixed and bugs remaining.

---

## How they work

1. **Mask.** Comments are blanked and string contents are masked, with every character position kept so line numbers stay correct. A `;` inside a string or a `toint` inside a comment cannot trigger anything.
2. **Split.** The rule is split into top-level statements on `;`. A statement that begins with `|` means a stray semicolon cut the query short.
3. **Check.** Each check is a small structural test, such as:
   - bracket-matched argument counts
   - the order of assignments inside an `extend`
   - whether a string literal is ever compared with `RegistryKey`, directly or through a `let` list

These are pattern checks, not a full KQL parser. They don't track which columns survive a `join` or `project`, so read **WARN** as "look at this line; it may be intentional".

---

## Checks

| ID | Severity | What it catches | Auto-fix |
|---|---|---|---|
| E01 | ERROR | `hklm\…` registry anchor compared with `RegistryKey`. Defender writes `HKEY_LOCAL_MACHINE\…`, so it never matches | ✅ when the hive starts the string |
| E02 | ERROR | `base64_decode_string()`, which does not exist | ✅ `base64_decode_tostring()` |
| E03 | ERROR | `min(a, b)` / `max(a, b)`, aggregations used as scalars | ✅ `min_of()` / `max_of()` |
| E04 | ERROR | `case()` without a final default value | ❌ needs a chosen default |
| E05 | ERROR | Column that doesn't exist in Defender (`InitiatingProcessSigner`, or Sysmon names such as `TargetObject` and `Image`) | ❌ needs the native column or a join |
| E06 | ERROR | Stray `;` that ends the query before a `\|` | ✅ |
| W01 | WARN | Prevalence baseline overlaps the detection window | ❌ |
| W02 | WARN | Rarity not guarded against an empty SHA256 | ❌ |
| W03 | WARN | `where` straight after a `leftouter` join | ❌ |
| W04 | WARN | Several `any()` pass-throughs in one `summarize` | ❌ |
| W05 | WARN | Penalty scoring with no floor at 0 | ❌ |
| W06 | WARN | Writer join on `DeviceId, InitiatingProcessId` that fans out | ❌ |
| W07 | WARN | DLL names matched against a process `FileName` | ❌ |
| W08 | WARN | Bin-based correlation that misses events across a bin edge | ❌ |
| W09 | WARN | `AccountName` on `DeviceRegistryEvents` | ❌ |
| W10 | WARN | `column_ifexists()` on a column Defender never has | ❌ |
| P01 | PORT | `toint(<condition>)`, which breaks arithmetic in the emulator | ✅ `iff(<condition>, 1, 0)` |
| P02 | PORT | Column used in the `extend` that defines it, which the emulator can't resolve | ✅ `extend` split |

- **ERROR:** the rule breaks, or part of it silently never matches, in Defender / Sentinel.
- **WARN:** a known bug class; it may be intentional.
- **PORT:** valid in production, but fails in the local ADX emulator (Kustainer). `--no-port` hides PORT findings in the linter and skips P01/P02 in the fixer.

---

## lint_kql.py

```powershell
python tools\lint_kql.py <rules folder or .kql files> [--no-port] [--md report.md]
```

| Option | Effect |
|---|---|
| `--no-port` | Hide emulator-only (PORT) findings |
| `--md FILE` | Also write a markdown report |

Folders are searched recursively for `.kql` files. The exit code is **1 if any ERROR is found**, so it can gate CI:

```yaml
- name: Lint rules
  run: python tools/lint_kql.py detections --no-port
```

---

## fix_kql.py

```powershell
python tools\fix_kql.py <rules folder or .kql files> [options]
```

| Option | Effect |
|---|---|
| `--out DIR` | Folder for corrected copies (default `fixed_rules`). Sub-folders are mirrored |
| `--report FILE` | Markdown change log (default `fix_report.md`) |
| `--dry-run` | Report only and write nothing |
| `--diff` | Print a unified diff for every changed rule |
| `--no-port` | Production fixes only; skip P01 and P02 |
| `--in-place` | Overwrite the originals. Use only inside a git repository, so `git diff` reviews the change and `git checkout -- <file>` undoes it |

### What each fix does

**E06: stray semicolon.** A `;` ends a KQL query, so the next pipe started a new, invalid statement:

```kusto
// before                                   // after
    UntrustedWriter = iff(...);                 UntrustedWriter = iff(...)
| where not(...)                            | where not(...)
```

**E01: short-hive registry anchor.** The hive prefix is removed. The path then matches Defender's `HKEY_LOCAL_MACHINE\…` and Sysmon's `HKLM\…` alike:

```kusto
@"hklm\system\currentcontrolset\control\lsa"   ->   @"system\currentcontrolset\control\lsa"
```

Only strings that are compared with `RegistryKey` are rewritten. An `hklm\` inside a command-line token list is left alone, because command lines really do contain it. A hive inside a regular expression is reported for a manual fix, not rewritten.

**E02 / E03: wrong function names.**

```kusto
base64_decode_string(x)            ->   base64_decode_tostring(x)
min(strlen(Cmd), 240)              ->   min_of(strlen(Cmd), 240)
```

**P01: `toint(<condition>)`.**

```kusto
toint(WriterTrustedPublisher == 0)  ->   iff(WriterTrustedPublisher == 0, 1, 0)
```

For true and false the result is identical. The one difference is a **null** condition: `iff()` returns the else value (0) where `toint()` returned null, and 0 is what a score wants.

**P02: column used in its own `extend`.** The `extend` is split where the dependency begins. This never changes results, because sequential `extend`s see the same values:

```kusto
// before                                   // after
| extend                                    | extend
    Score_RareWriter = 10 * WriterIsRare,       Score_RareWriter = 10 * WriterIsRare
    RiskScore = BaseScore + ...             | extend
                                                RiskScore = BaseScore + ...
```

### Safety

- **No overwrites by default.** Corrected copies go to `--out`. `--in-place` is opt-in.
- **Encoding is preserved.** A UTF-8 BOM and Windows line endings (CRLF) are kept as they were.
- **Idempotent.** Running the fixer on its own output changes nothing.
- **Line numbers in `fix_report.md` refer to the original file**, so you can review each change against your source.

### What it doesn't fix (and how to fix it by hand)

These need a judgement call. They appear as **MANUAL** in the output and in `fix_report.md`.

- **E04, `case()` default:** add a final value, e.g. `case(score >= 120, "CRITICAL", score >= 90, "HIGH", "LOW")`.
- **E05, phantom columns:** replace each one with its Defender equivalent (the linter names it). For publisher trust, join certificate data on the writer's hash:
  ```kusto
  | join kind=leftouter (
      DeviceFileCertificateInfo
      | summarize arg_max(Timestamp, Signer, IsTrusted) by SHA1
    ) on $left.InitiatingProcessSHA1 == $right.SHA1
  ```
- **W01, prevalence overlap:** end the baseline where detection starts: `| where Timestamp >= ago(30d) and Timestamp < ago(lookback)`.
- **W02, null-SHA rarity:** `IsRare = iff(isnotempty(SHA256) and DeviceCount <= 2, 1, 0)`.
- **W03, `where` after `leftouter`:** flag matches instead of filtering. Use `extend IsMatch = (...)`, then aggregate with `make_set_if` / `countif`.
- **W04, `any()` pass-through:** replace it with `arg_max(Timestamp, *)` so every column comes from the same row.
- **W05, negative scores:** add `| extend Score = max_of(Score, 0)` after the penalty block.
- **W06, writer join fan-out:** drop the `DeviceProcessEvents` join and read the `InitiatingProcess*` columns straight from the source table.
- **W07, DLL vs `FileName`:** match the DLL in `ProcessCommandLine`, or use `DeviceImageLoadEvents`.
- **W08, bin edges:** match each event against its own bin and the previous one, then filter on the real time difference.
- **W09, `AccountName`:** use `InitiatingProcessAccountName`.
- **W10, `column_ifexists()` on a missing column:** the branch is always empty; use the E05 fix instead.

---

## Limits

- **Pattern-based, not a parser.** Expect some false positives on unusual rules, and review WARNs rather than following them blindly.
- **Mechanical fixes only.** Anything that changes detection logic is left to you.
- **Static.** A rule can lint clean and still never fire. Only `run_tests.py` against real telemetry proves behaviour.
