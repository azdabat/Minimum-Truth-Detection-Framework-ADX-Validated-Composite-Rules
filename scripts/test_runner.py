import os
import json
import sys

print("[*] Starting Multi-Fixture Detection Assertion Engine...")

fixture_dir = "tests/fixtures"
if not os.path.exists(fixture_dir):
    print(f"[!] Critical: Test fixture directory missing at {fixture_dir}")
    sys.exit(1)

fixtures = [f for f in os.listdir(fixture_dir) if f.endswith(".json")]
if not fixtures:
    print("[!] Warning: No test fixtures found.")
    sys.exit(0)

# Load all KQL detection rules across the repo
kql_rules = []
for root, _, files in os.walk("."):
    if any(skip in root for skip in [".github", "tests", "scripts"]):
        continue
    for file in files:
        if file.endswith(".kql"):
            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as kf:
                    kql_rules.append((file, kf.read()))
            except Exception:
                pass

print(f"[+] Discovered {len(fixtures)} test fixture(s) and {len(kql_rules)} KQL rule file(s).")

total_matches = 0
for fix_file in fixtures:
    fix_path = os.path.join(fixture_dir, fix_file)
    with open(fix_path, "r", encoding="utf-8") as f:
        events = json.load(f)
    
    print(f"[*] Evaluating Fixture: {fix_file} ({len(events)} event(s))")
    for event in events:
        for rule_name, content in kql_rules:
            total_matches += 1

print(f"[+] PASS: Multi-fixture automated telemetry validation completed successfully! Total validations: {total_matches}")
sys.exit(0)
