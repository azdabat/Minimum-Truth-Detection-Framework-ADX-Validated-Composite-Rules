#!/usr/bin/env python3
"""
MTDF KQL linter — enforces the bug classes from
"KQL Detection Engineering — Common Implementation Errors".

Rules listed in tests/manifest.json are checked STRICTLY: any finding fails the pipeline.
Every other .kql/.KQL file in the repo is checked too, but findings are reported as
warnings so legacy and research rules never block a commit.

Checks
  E001  file is empty or corrupted (null bytes)
  E002  unbalanced ( ) [ ] { } outside strings and comments
  E003  any() aggregation — non-deterministic; use arg_max(Timestamp, *)        (Rule 1)
  E004  make_set(iff(...)) — use make_set_if(...)                                (Rule 2)
  W001  file name looks like KQL but has the wrong extension (",kql", ".sql")
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", ".github", "scripts", "tests", "node_modules"}
IN_ACTIONS = bool(os.environ.get("GITHUB_ACTIONS"))


def strip_strings_and_comments(text):
    """Blank out string literals and // comments, keeping line breaks so line numbers survive."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if text.startswith("//", i):                       # comment to end of line
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("```", i):                      # multi-line string
            end = text.find("```", i + 3)
            end = n if end == -1 else end + 3
            out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
            i = end
            continue
        verbatim = ch in "@" and i + 1 < n and text[i + 1] in "\"'"
        if verbatim or ch in "\"'":
            quote = text[i + 1] if verbatim else ch
            j = i + (2 if verbatim else 1)
            while j < n:
                if verbatim and text[j] == quote and j + 1 < n and text[j + 1] == quote:
                    j += 2
                    continue
                if not verbatim and text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote or text[j] == "\n":
                    break
                j += 1
            out.append(" " * (j + 1 - i))
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def check_file(path):
    findings = []
    raw = open(path, "rb").read()
    if b"\x00" in raw or len(raw.replace(b"\x00", b"").strip()) < 10:
        return [("E001", 1, "file is empty or corrupted (null bytes) — re-upload or delete it")]
    text = raw.decode("utf-8-sig", errors="replace")
    code = strip_strings_and_comments(text)

    pairs, stack = {")": "(", "]": "[", "}": "{"}, []
    for lineno, line in enumerate(code.split("\n"), 1):
        for ch in line:
            if ch in "([{":
                stack.append((ch, lineno))
            elif ch in pairs:
                if not stack or stack[-1][0] != pairs[ch]:
                    findings.append(("E002", lineno, f"unexpected '{ch}'"))
                    stack = []
                    break
                stack.pop()
    for ch, lineno in stack[:1]:
        findings.append(("E002", lineno, f"'{ch}' is never closed"))

    for lineno, line in enumerate(code.split("\n"), 1):
        if re.search(r"(?<![\w.])any\s*\(", line):
            findings.append(("E003", lineno, "any() is non-deterministic — use arg_max(Timestamp, *) (MTDF Rule 1)"))
        if re.search(r"\bmake_set\s*\(\s*(iif|iff)\s*\(", line):
            findings.append(("E004", lineno, "make_set(iff(...)) — use make_set_if(...) (MTDF Rule 2)"))
    return findings


def report(level, path, lineno, code, msg):
    rel = os.path.relpath(path, ROOT)
    if IN_ACTIONS:
        print(f"::{level} file={rel},line={lineno}::{code} {msg}")
    else:
        print(f"[{level.upper()}] {rel}:{lineno} {code} {msg}")


def main():
    strict = set()
    manifest = os.path.join(ROOT, "tests", "manifest.json")
    if os.path.exists(manifest):
        for t in json.load(open(manifest, encoding="utf-8")).get("tests", []):
            strict.add(os.path.normcase(os.path.join(ROOT, t["rule"])))

    errors = warnings = scanned = 0
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            lower = name.lower()
            if lower.endswith(",kql") or (lower.endswith(".sql") and re.search(
                    r"\|\s*(where|extend|project|summarize)\b", open(path, encoding="utf-8", errors="ignore").read())):
                report("warning", path, 1, "W001", "looks like a KQL rule but the extension is wrong — rename to .kql")
                warnings += 1
                continue
            if not lower.endswith(".kql"):
                continue
            scanned += 1
            is_strict = os.path.normcase(path) in strict
            for code, lineno, msg in check_file(path):
                if is_strict:
                    report("error", path, lineno, code, msg)
                    errors += 1
                else:
                    report("warning", path, lineno, code, msg)
                    warnings += 1

    missing = [p for p in strict if not os.path.exists(p)]
    for p in missing:
        report("error", p, 1, "E000", "rule listed in tests/manifest.json does not exist")
        errors += 1

    print(f"\n[*] Scanned {scanned} KQL file(s): {errors} error(s) in tested rules, {warnings} warning(s) elsewhere")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"## MTDF KQL lint\n\nScanned **{scanned}** rule files — "
                     f"**{errors}** error(s) in tested rules, **{warnings}** warning(s) in other rules.\n\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
