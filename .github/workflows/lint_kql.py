#!/usr/bin/env python3
"""
lint_kql.py - static linter for MTDF composite KQL rules (Microsoft Defender XDR / Sentinel).

Checks for the bug classes in "KQL Detection Engineering - Common Implementation Errors"
plus the ones found by testing rules against real Empire telemetry. It reads rule text;
it does not run it. Pair it with run_tests.py, which proves a rule actually fires.

Severity
  ERROR  breaks the rule, or makes part of it silently never match, in Defender / Sentinel
  WARN   a known bug class - review the flagged line; it may be intentional
  PORT   valid in production, but fails in the local ADX emulator (Kustainer)

    python tools/lint_kql.py C:\\path\\to\\rules                 # every .kql under a folder
    python tools/lint_kql.py rule.kql --no-port                # hide emulator-only findings
    python tools/lint_kql.py C:\\path\\to\\rules --md report.md  # also write a markdown report

Exit code is 1 if any ERROR is found, so it can gate CI.
"""
import argparse
import bisect
import os
import re
import sys
from collections import Counter

CHECKS = {
    "E01": ("ERROR", "Short-hive registry anchor never matches Defender"),
    "E02": ("ERROR", "base64_decode_string() does not exist"),
    "E03": ("ERROR", "min()/max() used as a scalar"),
    "E04": ("ERROR", "case() has no default branch"),
    "E05": ("ERROR", "Column does not exist in Defender tables"),
    "E06": ("ERROR", "Stray ';' ends the query before a pipe"),
    "W01": ("WARN", "Prevalence baseline overlaps the detection window"),
    "W02": ("WARN", "Rarity check not guarded against null SHA256"),
    "W03": ("WARN", "where right after a leftouter join (may become inner)"),
    "W04": ("WARN", "Multiple any() pass-through in one summarize"),
    "W05": ("WARN", "Penalty score can go negative with no floor"),
    "W06": ("WARN", "Writer join on DeviceId + InitiatingProcessId fans out"),
    "W07": ("WARN", "DLL names matched against process FileName"),
    "W08": ("WARN", "Bin-based correlation misses events across a bin edge"),
    "W09": ("WARN", "AccountName is not a DeviceRegistryEvents column"),
    "W10": ("WARN", "column_ifexists() on a column Defender never has"),
    "P01": ("PORT", "toint(<condition>) - use iff(<condition>, 1, 0)"),
    "P02": ("PORT", "Column used in the same extend that defines it"),
}

# Sysmon / non-MDE names that do not exist as columns in Defender Device* tables.
PHANTOM = {
    "InitiatingProcessSigner": "join DeviceFileCertificateInfo on InitiatingProcessSHA1 and use Signer / IsTrusted",
    "TargetProcessName": "Defender uses FileName / FolderPath for the target process",
    "ProcessName": "use FileName",
    "Image": "use FolderPath / FileName",
    "ParentImage": "use InitiatingProcessFolderPath / InitiatingProcessFileName",
    "CommandLine": "use ProcessCommandLine",
    "ParentCommandLine": "use InitiatingProcessCommandLine",
    "TargetFilename": "use FolderPath / FileName",
    "TargetObject": "use RegistryKey",
    "Details": "use RegistryValueData",
    "SourceImage": "use InitiatingProcessFolderPath",
    "TargetImage": "use FolderPath / FileName",
    "Hashes": "use SHA256 / SHA1 / MD5",
    "GrantedAccess": "DeviceEvents carries it inside AdditionalFields",
    "CallTrace": "DeviceEvents carries it inside AdditionalFields",
    "ProcessGuid": "Defender has no GUID; use DeviceId + ProcessId + ProcessCreationTime",
    "ParentProcessGuid": "use DeviceId + InitiatingProcessId + InitiatingProcessCreationTime",
    "EventID": "Defender uses ActionType",
}
OTHER_TABLES = re.compile(
    r"\b(SecurityEvent|Event|SysmonEvent|WindowsEvent|Syslog|CommonSecurityLog|DnsEvents|SigninLogs|"
    r"AuditLogs|OfficeActivity|Identity\w+|CloudAppEvents|Email\w+|AlertEvidence|AlertInfo|AzureActivity)\b")
HIVE = re.compile(r"(?i)\bhk\s?(lm|cu|cr|u)\\")
BOOL_OPS = re.compile(r"==|!=|<=|>=|<|>|\b(and|or|not|has|has_any|has_all|has_cs|in|matches|contains|"
                      r"startswith|endswith|isnotempty|isempty|isnull|isnotnull)\b|\bin~")


class Source:
    """Rule text with comments blanked and string contents masked, positions preserved."""

    def __init__(self, text):
        self.text = text
        self.strings = []                       # (start, end, value)
        code = list(text)
        i, n = 0, len(text)
        while i < n:
            if text.startswith("//", i):
                j = text.find("\n", i)
                j = n if j == -1 else j
                for k in range(i, j):
                    code[k] = " "
                i = j
                continue
            verbatim = text[i] == "@" and i + 1 < n and text[i + 1] in "\"'"
            if verbatim or text[i] in "\"'":
                q = text[i + 1] if verbatim else text[i]
                j = i + (2 if verbatim else 1)
                buf = []
                while j < n:
                    c = text[j]
                    if c == q:
                        if verbatim and j + 1 < n and text[j + 1] == q:
                            buf.append(q)
                            j += 2
                            continue
                        break
                    if not verbatim and c == "\\" and j + 1 < n:
                        buf.append(text[j:j + 2])
                        j += 2
                        continue
                    if c == "\n" and not verbatim:
                        break
                    buf.append(c)
                    j += 1
                end = min(j + 1, n)
                self.strings.append((i, end, "".join(buf)))
                for k in range(i, end):
                    if code[k] != "\n":
                        code[k] = "S"
                i = end
                continue
            i += 1
        self.code = "".join(code)
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def line(self, pos):
        return bisect.bisect_right(self.line_starts, pos)

    def line_text(self, pos):
        s = self.line_starts[self.line(pos) - 1]
        e = self.code.find("\n", s)
        return self.code[s:e if e != -1 else len(self.code)]


def matching_paren(code, open_idx):
    depth = 0
    for k in range(open_idx, len(code)):
        if code[k] in "([{":
            depth += 1
        elif code[k] in ")]}":
            depth -= 1
            if depth == 0:
                return k
    return len(code) - 1


def call_args(code, open_idx):
    """Top-level comma-separated argument spans of the call whose '(' is at open_idx."""
    close = matching_paren(code, open_idx)
    args, depth, start = [], 0, open_idx + 1
    for k in range(open_idx + 1, close):
        c = code[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            args.append((start, k))
            start = k + 1
    if code[start:close].strip():
        args.append((start, close))
    return args


def statements(code):
    """(start, end) spans of top-level ';'-separated statements."""
    spans, depth, start = [], 0, 0
    for k, c in enumerate(code):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth = max(0, depth - 1)
        elif c == ";" and depth == 0:
            spans.append((start, k))
            start = k + 1
    spans.append((start, len(code)))
    return [s for s in spans if s[0] < s[1] and code[s[0]:s[1]].strip()]


def clause_end(code, start):
    """End of a pipe clause: next depth-0 '|' or ';' after start."""
    depth = 0
    for k in range(start, len(code)):
        c = code[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c in "|;":
            return k
    return len(code)


def assignments(code, start, end):
    """[(name, expr_start, expr_end)] for 'a = x, b = y' between start and end (top level)."""
    parts, depth, s = [], 0, start
    for k in range(start, end):
        c = code[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append((s, k))
            s = k + 1
    parts.append((s, end))
    out = []
    for a, b in parts:
        m = re.match(r"\s*(\w+)\s*=(?!=)", code[a:b])
        if m:
            out.append((m.group(1), a + m.end(), b))
    return out


def is_defined(code, name):
    """True if the rule defines `name` itself (let or an assignment that doesn't read it)."""
    if re.search(rf"\blet\s+{name}\b", code):
        return True
    for m in re.finditer(rf"(?<![\w.$]){name}\s*=(?!=)", code):
        rhs_end = clause_end(code, m.end())
        nxt = re.search(r",\s*\w+\s*=(?!=)|\n", code[m.end():rhs_end])
        rhs = code[m.end(): m.end() + nxt.start()] if nxt else code[m.end():rhs_end]
        if not re.search(rf"\b{name}\b", rhs):
            return True
    return False


def lint(text):
    src = Source(text)
    code = src.code
    out = []

    def add(cid, pos, msg):
        out.append((cid, src.line(pos), msg))

    stmts = statements(code)
    let_names = {}
    for a, b in stmts:
        m = re.match(r"\s*let\s+(\w+)\s*=", code[a:b])
        if m:
            let_names[m.group(1)] = (a, b)

    def enclosing_let(pos):
        for name, (a, b) in let_names.items():
            if a <= pos < b:
                return name, a, b
        return None

    uses_device = bool(re.search(r"\bDevice\w+\b", code))
    mixed = bool(OTHER_TABLES.search(code))

    # E06 stray semicolon
    for a, b in stmts:
        body = code[a:b]
        lead = len(body) - len(body.lstrip())
        if body.lstrip().startswith("|"):
            add("E06", a + lead, "a ';' above ends the query, so this pipe starts a new, invalid statement - remove the ';'")

    # E01 short-hive anchors compared with RegistryKey
    reg_terms = {"RegistryKey", "PreviousRegistryKey"}
    for m in re.finditer(r"\b(\w+)\s*=(?!=)[^,\n]*\bRegistryKey\b", code):
        reg_terms.add(m.group(1))
    reg_rx = re.compile(r"\b(" + "|".join(map(re.escape, reg_terms)) + r")\b")
    for s, e, val in src.strings:
        if not HIVE.search(val):
            continue
        hit = bool(reg_rx.search(src.line_text(s)))
        enc = enclosing_let(s)
        if not hit and enc:
            name, la, lb = enc
            for u in re.finditer(rf"\b{name}\b", code):
                if not (la <= u.start() < lb) and reg_rx.search(src.line_text(u.start())):
                    hit = True
                    break
        if hit:
            add("E01", s, f'"{val[:60]}" never matches: Defender writes HKEY_LOCAL_MACHINE\\... - '
                          r"use a hive-agnostic path such as system\currentcontrolset\...")

    # E02 base64_decode_string
    for m in re.finditer(r"\bbase64_decode_string\s*\(", code):
        add("E02", m.start(), "function does not exist - use base64_decode_tostring()")

    # E03 scalar min/max
    for m in re.finditer(r"\b(min|max)\s*\(", code):
        if len(call_args(code, m.end() - 1)) >= 2:
            add("E03", m.start(), f"{m.group(1)}() is an aggregation (one argument) - use {m.group(1)}_of()")

    # E04 case() arity
    for m in re.finditer(r"\bcase\s*\(", code):
        if len(call_args(code, m.end() - 1)) % 2 == 0:
            add("E04", m.start(), "case() needs condition/value pairs plus a final default value")

    # E05 phantom columns, W09 AccountName on DeviceRegistryEvents
    if uses_device:
        for name, fix in PHANTOM.items():
            m = re.search(rf"(?<![\w.$]){name}\b", code)
            if m and not is_defined(code, name):
                cid = "E05"
                note = " (ignore if it belongs to a non-Defender table in this rule)" if mixed else ""
                add(cid, m.start(), f"{name} is not a Defender column - {fix}{note}")
        if re.search(r"\bDeviceRegistryEvents\b", code):
            m = re.search(r"(?<![\w.$])AccountName\b", code)
            if m and not is_defined(code, "AccountName"):
                add("W09", m.start(), "if this resolves against DeviceRegistryEvents it fails in Defender - "
                                      "use InitiatingProcessAccountName")

    # W01 prevalence overlap
    for name, (a, b) in let_names.items():
        body = code[a:b]
        if re.search(r"(?i)prevalen|rarity|baseline|history", name) and "summarize" in body and "ago(" in body:
            if not re.search(r"<\s*ago\s*\(", body) and not re.search(r"\bbetween\b", body):
                add("W01", a, f"{name}: baseline has no upper bound - add 'and Timestamp < ago(lookback)'")

    # W02 null-SHA rarity
    if re.search(r"\bon\b[^|;]*SHA256", code):
        for m in re.finditer(r"\b\w*(Count|Prevalence|Seen)\w*\s*<=\s*\d", code):
            if "isnotempty" not in src.line_text(m.start()):
                add("W02", m.start(), "rarity fires for empty SHA256 - guard with isnotempty(<SHA>) and ...")

    # W03 / W06 joins
    for m in re.finditer(r"\bjoin\b", code):
        k, depth = m.end(), 0
        on_pos = None
        while k < len(code):
            c = code[k]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0 and c in "|;":
                break
            elif depth == 0 and re.match(r"\bon\b", code[k:k + 3]) and not code[k - 1].isalnum():
                on_pos = k
                break
            k += 1
        if on_pos is None:
            continue
        on_end = clause_end(code, on_pos)
        segment = code[m.start():on_end]
        if re.search(r"kind\s*=\s*leftouter", segment) and on_end < len(code) and code[on_end] == "|":
            nxt = re.match(r"\|\s*(\w+)", code[on_end:])
            if nxt and nxt.group(1) == "where":
                add("W03", on_end, "check this where doesn't filter right-side columns - unmatched (null) rows "
                                   "get dropped; flag with extend IsMatch and aggregate instead")
        if "DeviceProcessEvents" in segment and re.search(
                r"\bon\s+(DeviceId\s*,\s*InitiatingProcessId|InitiatingProcessId\s*,\s*DeviceId)\b", code[on_pos:on_end]):
            add("W06", on_pos, "matches the writer PID against the PARENT PID of process creates: one row per child, "
                               "misses writers with no children - read InitiatingProcess* from the source table")

    # W04 multiple any()
    for m in re.finditer(r"\bsummarize\b", code):
        clause = code[m.start():clause_end(code, m.end())]
        if len(re.findall(r"\bany\s*\(", clause)) >= 2:
            add("W04", m.start(), "columns may come from different rows - use arg_max(Timestamp, *)")

    # W05 negative score, P02 same-extend references
    for m in re.finditer(r"\bextend\b", code):
        end = clause_end(code, m.end())
        seen = []
        for name, ea, eb in assignments(code, m.end(), end):
            expr = code[ea:eb]
            if re.search(r"[,(]\s*-\s*\d", expr) and not re.search(
                    rf"\b{name}\s*<\s*0|max_of\s*\([^)]*\b{name}\b", code[eb:]):
                add("W05", ea, f"{name} can go below 0 - floor it: extend {name} = max_of({name}, 0)")
            refs = [p for p in seen if re.search(rf"\b{p}\b", expr)]
            if refs:
                add("P02", ea, f"{name} uses {', '.join(refs)} from the same extend - split into a second extend")
            seen.append(name)

    # W07 DLL names vs FileName
    if "DeviceProcessEvents" in code:
        for name, (a, b) in let_names.items():
            vals = [v for s, e, v in src.strings if a <= s < b]
            if any(re.search(r"(?i)\.dll$", v.strip()) for v in vals):
                u = re.search(rf"\bFileName\s+(in~|in|has_any|has_all|has|=~|==)\s*\(?\s*{name}\b", code)
                if u:
                    add("W07", u.start(), f"{name} holds DLL names but DeviceProcessEvents.FileName is the executable - "
                                          "match ProcessCommandLine or use DeviceImageLoadEvents")

    # W08 bin boundary
    if re.search(r"\bbin\s*\(\s*\w*Timestamp", code):
        for m in re.finditer(r"\bon\b[^|;]*\b\w*Bin\w*\b", code):
            add("W08", m.start(), "events either side of a bin edge never correlate - match the current and previous "
                                  "bin, then filter on the real time difference")
            break

    # W10 column_ifexists on columns Defender never has
    for s, e, val in src.strings:
        if val in ("InitiatingProcessSigner", "TargetProcessName") and \
                re.search(r"column_ifexists\s*\(\s*$", src.text[max(0, s - 40):s]):
            add("W10", s, f"{val} never exists in Defender, so this branch is always empty - "
                          "join DeviceFileCertificateInfo instead")

    # P01 toint(<condition>)
    for m in re.finditer(r"\btoint\s*\(", code):
        args = call_args(code, m.end() - 1)
        if args and BOOL_OPS.search(code[args[0][0]:args[0][1]]):
            add("P01", m.start(), "toint(<condition>) - use iff(<condition>, 1, 0)")

    return sorted(out, key=lambda f: (f[1], f[0]))


def main():
    ap = argparse.ArgumentParser(description="Static linter for MTDF KQL rules.")
    ap.add_argument("paths", nargs="+", help=".kql files and/or folders (searched recursively)")
    ap.add_argument("--no-port", action="store_true", help="hide PORT (emulator-only) findings")
    ap.add_argument("--md", help="also write a markdown report to this file")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        if os.path.isdir(p):
            for d, _, fs in os.walk(p):
                files += [os.path.join(d, f) for f in fs if f.lower().endswith(".kql")]
        elif p.lower().endswith(".kql"):
            files.append(p)
    files.sort()
    if not files:
        print("no .kql files found")
        return 1

    totals, results = Counter(), []
    for f in files:
        with open(f, encoding="utf-8-sig", errors="replace") as fh:
            findings = lint(fh.read())
        if args.no_port:
            findings = [x for x in findings if CHECKS[x[0]][0] != "PORT"]
        results.append((f, findings))
        totals.update(x[0] for x in findings)

    for f, findings in results:
        if not findings:
            continue
        print(f"\n{f}")
        for cid, line, msg in findings:
            print(f"  {CHECKS[cid][0]:<5} {cid}  L{line:<4} {msg}")

    sev = Counter()
    for cid, n in totals.items():
        sev[CHECKS[cid][0]] += n
    bad = sum(1 for _, fs in results if any(CHECKS[c][0] == "ERROR" for c, _, _ in fs))
    print(f"\n{len(files)} rules scanned | {bad} with errors | "
          f"{sev['ERROR']} ERROR, {sev['WARN']} WARN, {sev['PORT']} PORT")
    for cid in sorted(totals):
        print(f"  {cid} {CHECKS[cid][0]:<5} x{totals[cid]:<3} {CHECKS[cid][1]}")

    if args.md:
        lines = ["# MTDF lint report", "",
                 f"{len(files)} rules scanned, {bad} with errors. "
                 f"{sev['ERROR']} errors, {sev['WARN']} warnings, {sev['PORT']} portability findings.", "",
                 "| Check | Severity | Count | Meaning |", "|---|---|---|---|"]
        lines += [f"| {c} | {CHECKS[c][0]} | {totals[c]} | {CHECKS[c][1]} |" for c in sorted(totals)]
        for f, findings in results:
            if findings:
                lines += ["", f"## {os.path.basename(f)}", "", "| Line | Check | Finding |", "|---|---|---|"]
                lines += [f"| {ln} | {CHECKS[c][0]} {c} | {m.replace('|', '/')} |" for c, ln, m in findings]
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"\nreport written to {args.md}")

    return 1 if sev["ERROR"] else 0


if __name__ == "__main__":
    sys.exit(main())
