#!/usr/bin/env python3
"""
fix_kql.py - apply the purely mechanical lint fixes to MTDF KQL rules.

Pairs with lint_kql.py (imports its parser - keep both files in the same folder).
By default it NEVER touches your originals: corrected copies go to a separate
folder, with a markdown change log. Everything the linter reports that needs a
judgement call is listed as "manual" in the log, not rewritten.

  Fix   Rewrite
  E06   stray ';' before a pipe          -> ';' removed
  E02   base64_decode_string(            -> base64_decode_tostring(
  E03   min(a, b) / max(a, b)            -> min_of(a, b) / max_of(a, b)
  E01   "hklm\\..." registry anchor       -> "..." (hive-agnostic)
  P01   toint(<condition>)               -> iff(<condition>, 1, 0)
  P02   column used in its own extend    -> extend split at that point

    python tools/fix_kql.py C:\\rules                    # copies -> fixed_rules\\, log -> fix_report.md
    python tools/fix_kql.py C:\\rules --dry-run --diff   # show what would change, write nothing
    python tools/fix_kql.py C:\\rules --no-port          # production fixes only (skip P01, P02)
    python tools/fix_kql.py C:\\rules --in-place         # overwrite originals (only in a git repo)
"""
import argparse
import difflib
import os
import re
import sys
from collections import Counter

import lint_kql as L

FIXES = {
    "E06": "removed ';' that ended the query before a pipe",
    "E02": "base64_decode_string -> base64_decode_tostring",
    "E03": "min/max with two arguments -> min_of/max_of",
    "E01": "short-hive registry anchor -> hive-agnostic path",
    "P01": "toint(<condition>) -> iff(<condition>, 1, 0)",
    "P02": "extend split so no column is used in the extend that defines it",
}
AUTO = set(FIXES)


def apply_edits(text, edits):
    """edits: (start, end, replacement); applied right-to-left so offsets stay valid."""
    for s, e, r in sorted(edits, key=lambda x: x[0], reverse=True):
        text = text[:s] + r + text[e:]
    return text


def fix_semicolons(text):
    src, edits, log = L.Source(text), [], []
    code, depth = src.code, 0
    for k, c in enumerate(code):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth = max(0, depth - 1)
        elif c == ";" and depth == 0 and code[k + 1:].lstrip().startswith("|"):
            edits.append((k, k + 1, ""))
            log.append(("E06", src.line(k), "removed ';' so the following pipe continues the query"))
    return apply_edits(text, edits), log


def fix_base64(text):
    src, edits, log = L.Source(text), [], []
    for m in re.finditer(r"\bbase64_decode_string(?=\s*\()", src.code):
        edits.append((m.start(), m.end(), "base64_decode_tostring"))
        log.append(("E02", src.line(m.start()), "base64_decode_string -> base64_decode_tostring"))
    return apply_edits(text, edits), log


def fix_minmax(text):
    src, edits, log = L.Source(text), [], []
    for m in re.finditer(r"\b(min|max)\s*\(", src.code):
        if len(L.call_args(src.code, m.end() - 1)) >= 2:
            name = m.group(1)
            edits.append((m.start(), m.start() + len(name), name + "_of"))
            log.append(("E03", src.line(m.start()), f"{name}( -> {name}_of("))
    return apply_edits(text, edits), log


def fix_hive(text):
    src, edits, log, manual = L.Source(text), [], [], []
    for s, e, val in L.hive_anchor_strings(src):
        raw = text[s:e]
        m = re.match(r"(@?[\"'])\s*hk\s?(lm|cu|cr|u)\\+", raw, re.I)
        if m:
            new = m.group(1) + raw[m.end():]
            edits.append((s, e, new))
            log.append(("E01", src.line(s), f"{raw[:70]} -> {new[:70]}"))
        else:
            manual.append(("E01", src.line(s), f"hive is not at the start of {raw[:60]} - edit by hand"))
    return apply_edits(text, edits), log, manual


def fix_toint(text):
    """toint(<condition>) -> iff(<condition>, 1, 0). Outermost first, repeated for nested calls."""
    log = []
    for _ in range(20):
        src = L.Source(text)
        code = src.code
        calls = []
        for m in re.finditer(r"\btoint\s*\(", code):
            open_idx = m.end() - 1
            args = L.call_args(code, open_idx)
            if len(args) == 1 and L.BOOL_OPS.search(code[args[0][0]:args[0][1]]):
                calls.append((m.start(), open_idx, L.matching_paren(code, open_idx)))
        outer = [c for c in calls if not any(o[0] < c[0] and c[2] < o[2] for o in calls)]
        if not outer:
            break
        edits = []
        for start, open_idx, close in outer:
            edits.append((start, open_idx, "iff"))       # 'toint' (+ any spaces) -> 'iff'
            edits.append((close, close, ", 1, 0"))        # insert before ')'
            log.append(("P01", src.line(start), "toint(<condition>) -> iff(<condition>, 1, 0)"))
        text = apply_edits(text, edits)
    return text, log


def _parts(code, start, end):
    """Top-level comma-separated parts: (start, end, comma_before_or_None)."""
    parts, depth, s, prev = [], 0, start, None
    for k in range(start, end):
        c = code[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append((s, k, prev))
            prev, s = k, k + 1
    parts.append((s, end, prev))
    return parts


def fix_split_extends(text):
    src, edits, log = L.Source(text), [], []
    code = src.code
    for m in re.finditer(r"\bextend\b", code):
        end = L.clause_end(code, m.end())
        line_start = src.line_starts[src.line(m.start()) - 1]
        indent = re.match(r"[ \t]*", text[line_start:]).group(0)
        group = set()
        for a, b, comma in _parts(code, m.end(), end):
            mm = re.match(r"\s*(\w+)\s*=(?!=)", code[a:b])
            if not mm:
                continue
            name, expr = mm.group(1), code[a + mm.end():b]
            refs = sorted(p for p in group if re.search(rf"\b{re.escape(p)}\b", expr))
            if refs and comma is not None:
                edits.append((comma, comma + 1, "\n" + indent + "| extend"))
                log.append(("P02", src.line(a + mm.start(1)), f"new extend before {name} (it uses {', '.join(refs)})"))
                group = set()
            group.add(name)
    return apply_edits(text, edits), log


def fix_text(text, skip=()):
    """Run every enabled fix in a safe order. Returns (fixed_text, applied_log, manual_list).
    Line numbers in the log refer to the ORIGINAL file (no fix before P02 adds or removes lines)."""
    applied, manual = [], []
    if "E06" not in skip:
        text, log = fix_semicolons(text); applied += log
    if "E02" not in skip:
        text, log = fix_base64(text); applied += log
    if "E03" not in skip:
        text, log = fix_minmax(text); applied += log
    if "E01" not in skip:
        text, log, man = fix_hive(text); applied += log; manual += man
    if "P01" not in skip:
        text, log = fix_toint(text); applied += log
    if "P02" not in skip:
        text, log = fix_split_extends(text); applied += log
    for cid, line, msg in L.lint(text):
        if cid not in AUTO or cid in skip:
            manual.append((cid, None, msg))
    return text, sorted(applied, key=lambda x: (x[1], x[0])), manual


def read_rule(path):
    raw = open(path, "rb").read()
    bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig", errors="replace")
    eol = "\r\n" if "\r\n" in text else "\n"
    return text.replace("\r\n", "\n"), bom, eol


def write_rule(path, text, bom, eol):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig" if bom else "utf-8", newline="") as fh:
        fh.write(text.replace("\n", eol))


def main():
    ap = argparse.ArgumentParser(description="Apply mechanical lint fixes to MTDF KQL rules.")
    ap.add_argument("paths", nargs="+", help=".kql files and/or folders (searched recursively)")
    ap.add_argument("--out", default="fixed_rules", help="folder for corrected copies (default: fixed_rules)")
    ap.add_argument("--report", default="fix_report.md", help="markdown change log (default: fix_report.md)")
    ap.add_argument("--in-place", action="store_true", help="overwrite the originals - use only in a git repo")
    ap.add_argument("--dry-run", action="store_true", help="write nothing; just report")
    ap.add_argument("--diff", action="store_true", help="print a unified diff for each changed rule")
    ap.add_argument("--no-port", action="store_true", help="skip emulator-only fixes (P01, P02)")
    args = ap.parse_args()

    skip = {"P01", "P02"} if args.no_port else set()
    jobs = []                                   # (source path, relative output path)
    for p in args.paths:
        if os.path.isdir(p):
            for d, _, fs in os.walk(p):
                for f in fs:
                    if f.lower().endswith(".kql"):
                        full = os.path.join(d, f)
                        jobs.append((full, os.path.relpath(full, p)))
        elif p.lower().endswith(".kql"):
            jobs.append((p, os.path.basename(p)))
    jobs.sort()
    if not jobs:
        print("no .kql files found")
        return 1

    applied_total, manual_total, results = Counter(), Counter(), []
    for path, rel in jobs:
        text, bom, eol = read_rule(path)
        fixed, applied, manual = fix_text(text, skip)
        changed = fixed != text
        applied_total.update(c for c, _, _ in applied)
        manual_total.update(c for c, _, _ in manual)
        results.append((rel, applied, manual, changed))

        if changed or manual:
            print(f"\n{rel}")
            for cid, line, msg in applied:
                print(f"  FIXED  {cid}  L{line:<4} {msg}")
            for cid, line, msg in manual:
                print(f"  MANUAL {cid}  {msg}")
        if args.diff and changed:
            sys.stdout.writelines(l + "\n" for l in difflib.unified_diff(
                text.splitlines(), fixed.splitlines(), f"a/{rel}", f"b/{rel}", lineterm=""))

        if args.dry_run:
            continue
        if args.in_place:
            if changed:
                write_rule(path, fixed, bom, eol)
        else:
            write_rule(os.path.join(args.out, rel), fixed, bom, eol)

    n_changed = sum(1 for r in results if r[3])
    print(f"\n{len(jobs)} rules scanned | {n_changed} changed | "
          f"{sum(applied_total.values())} fixes applied | {sum(manual_total.values())} findings need a manual fix")
    for cid in sorted(applied_total):
        print(f"  FIXED  {cid} x{applied_total[cid]:<3} {FIXES[cid]}")
    for cid in sorted(manual_total):
        print(f"  MANUAL {cid} x{manual_total[cid]:<3} {L.CHECKS[cid][1]}")

    if args.dry_run:
        print("\ndry run - nothing written")
        return 0

    where = "originals overwritten" if args.in_place else f"corrected copies in {args.out}{os.sep}"
    lines = ["# MTDF fix report", "",
             f"{len(jobs)} rules scanned, {n_changed} changed, {sum(applied_total.values())} mechanical fixes applied "
             f"({where}). {sum(manual_total.values())} findings still need a manual fix.", "",
             "| Fix | Count | Rewrite |", "|---|---|---|"]
    lines += [f"| {c} | {applied_total[c]} | {FIXES[c]} |" for c in sorted(applied_total)]
    if manual_total:
        lines += ["", "| Manual | Count | Issue |", "|---|---|---|"]
        lines += [f"| {c} | {manual_total[c]} | {L.CHECKS[c][1]} |" for c in sorted(manual_total)]
    for rel, applied, manual, changed in results:
        if not (applied or manual):
            continue
        lines += ["", f"## {rel}", ""]
        if applied:
            lines += ["| Line | Fix | Change |", "|---|---|---|"]
            lines += [f"| {ln} | {c} | {m.replace('|', '/')} |" for c, ln, m in applied]
        if manual:
            lines += ["", "Still needs a manual fix:", ""]
            lines += [f"- **{c}** {m}" for c, _, m in manual]
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\n{where} | change log: {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
