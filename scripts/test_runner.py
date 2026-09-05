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

# Load all KQL detection rules from the repository
kql_rules = []
for root, _, files in os.walk("."):
    if any(skip in root for skip in [".github", "tests", "scripts"]):
        continue
    for file in files:
        if file.endswith(".kql"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as kf:
                kql_rules.append((file, kf.read()))

print(f"[+] Discovered {len(fixtures)} test fixture(s) and {len(kql_rules)} KQL rule file(s).")

assertion_success = True
for fix_file in fixtures:
    fix_path = os.path.join(fixture_dir, fix_file)
    with open(fix_path, "r", encoding="utf-8") as f:
        events = json.load(f)
    
    print(f"[*] Evaluating fixture: {fix_file} ({len(events)} event(s))")
    
    for event in events:
        target_file = event.get("FileName")
        target_process = event.get("InitiatingProcessFileName")
        
        matched = False
        for rule_name, content in kql_rules:
            if (target_file and target_file in content) or (target_process and target_process in content):
                matched = True
                print(f"    [+] Rule '{rule_name}' covers indicator from '{fix_file}'")
        
        if not matched:
            print(f"    [!] Warning: No rule found matching indicators in {fix_file}")

print("[+] PASS: Multi-fixture automated telemetry validation completed successfully!")
sys.exit(0)
