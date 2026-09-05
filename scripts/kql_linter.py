import os
import sys

print("[*] Starting Detection-as-Code Syntax Check...")

mismatches = 0
for root, _, files in os.walk("."):
    for file in files:
        if file.endswith(".kql") or file.endswith(".md"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
                if text.count("(") != text.count(")"):
                    print(f"[!] Warning: Mismatched () in {path}")
                    mismatches += 1

if mismatches == 0:
    print("[+] PASS: All KQL rules and docs passed basic syntax checks!")
    sys.exit(0)
else:
    print(f"[!] FAIL: Found {mismatches} file(s) with mismatched syntax.")
    sys.exit(1)
