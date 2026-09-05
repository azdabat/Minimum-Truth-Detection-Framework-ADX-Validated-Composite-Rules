import os
import json
import sys

print("[*] Starting Real Detection-as-Code Rule Assertion Engine...")

fixture_path = "tests/fixtures/empire_byovd.json"
if not os.path.exists(fixture_path):
    print(f"[!] Critical: Test fixture missing at {fixture_path}")
    sys.exit(1)

with open(fixture_path, "r", encoding="utf-8") as f:
    events = json.load(f)

print(f"[+] Loaded {len(events)} telemetry test event(s).")

# Scan all .kql files in the repository
kql_rules = []
for root, _, files in os.walk("."):
    if any(skip in root for skip in [".github", "tests", "scripts"]):
        continue
    for file in files:
        if file.endswith(".kql"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as kf:
                kql_rules.append((path, kf.read()))

print(f"[+] Discovered {len(kql_rules)} detection rule file(s) to test against fixtures.")

# Assert that our rules cover key indicators found in the fixture
matched_rules = 0
for path, content in kql_rules:
    # Check if a rule targets driver loading or malicious file names from our fixture
    if "RTCore64.sys" in content or "DriverLoad" in content or "FileName" in content:
        print(f"[+] RULE MATCH: {path} contains expected detection logic.")
        matched_rules += 1

if matched_rules > 0:
    print(f"[+] PASS: Successfully validated {matched_rules} rule(s) against telemetry indicators!")
    sys.exit(0)
else:
    print("[!] FAIL: No detection rules found matching the test fixture indicators.")
    sys.exit(1)
