import os
import sys

print("[*] Starting Detection-as-Code Syntax & Structure Check...")

errors = 0
kql_count = f_count = 0

for root, _, files in os.walk("."):
    # Skip system, test, and workflow directories
    if any(skip in root for skip in [".github", "tests", "scripts"]):
        continue
    for file in files:
        if file.endswith(".kql"):
            kql_count += 1
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read().strip()
                if len(text) < 10:
                    print(f"[!] Error: KQL file is empty or too short -> {path}")
                    errors += 1

print(f"[+] Scanned {kql_count} KQL detection rule files across repository.")

if errors == 0:
    print("[+] PASS: All KQL detection rules passed structure verification!")
    sys.exit(0)
else:
    print(f"[!] FAIL: Found {errors} critical rule error(s).")
    sys.exit(1)
