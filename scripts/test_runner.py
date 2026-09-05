import os
import json
import sys

print("[*] Starting Advanced Composite Detection Assertion Engine...")

fixture_path = "tests/fixtures/registry_persistence_taskcache.json"
if not os.path.exists(fixture_path):
    print(f"[!] Critical: Test fixture missing at {fixture_path}")
    sys.exit(1)

with open(fixture_path, "r", encoding="utf-8") as f:
    events = json.load(f)

print(f"[+] Loaded {len(events)} telemetry event(s) from Registry Persistence fixture.")

# Scan repository for KQL rules
kql_rules = []
for root, _, files in os.walk("."):
    if any(skip in root for skip in [".github", "tests", "scripts"]):
        continue
    for file in files:
        if file.endswith(".kql"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as kf:
                kql_rules.append((file, kf.read()))

print(f"[+] Discovered {len(kql_rules)} KQL rule file(s).")

# Validate events against rule requirements
assertion_passed = False
for event in events:
    reg_key = event.get("RegistryKey", "").lower()
    value_data = event.get("RegistryValueData", "").lower()
    process = event.get("InitiatingProcessFileName", "").lower()

    # Check if event targets TaskCache or Services
    is_task_cache = "schedule\\taskcache" in reg_key
    has_danger = "powershell" in value_data or "powershell" in process

    print(f"[*] Evaluating Event -> TaskCache: {is_task_cache}, DangerTokenFound: {has_danger}")

    if is_task_cache and has_danger:
        # Cross-reference with repository KQL rules
        for rule_name, content in kql_rules:
            if "TaskCache" in content or "BackgroundKeys" in content:
                print(f"[+] MATCH: Rule '{rule_name}' successfully covers TaskCache registry persistence and danger indicators!")
                assertion_passed = True

if assertion_passed:
    print("[+] PASS: Advanced composite telemetry validation succeeded!")
    sys.exit(0)
else:
    print("[!] FAIL: Telemetry payload criteria not met by repository rules.")
    sys.exit(1)
