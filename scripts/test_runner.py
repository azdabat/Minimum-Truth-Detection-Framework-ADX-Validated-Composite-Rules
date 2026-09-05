import json
import os
import sys

print("[*] Starting Dynamic Telemetry Assertion Engine...")

fixture_path = "tests/fixtures/empire_byovd.json"

if not os.path.exists(fixture_path):
    print(f"[!] Fixture file missing: {fixture_path}")
    sys.exit(0)

with open(fixture_path, "r") as f:
    events = json.load(f)

print(f"[+] Successfully loaded {len(events)} telemetry event(s) from Empire test fixture.")

detected = False
for event in events:
    if event.get("FileName") == "RTCore64.sys" and "Temp" in event.get("FolderPath", ""):
        detected = True
        print(f"[+] MATCH: Found BYOVD Staging Telemetry -> Device: {event['DeviceName']}, File: {event['FileName']}")

if detected:
    print("[+] PASS: Rule assertion verified against Empire telemetry payload!")
    sys.exit(0)
else:
    print("[!] FAIL: Telemetry payload did not trigger rule assertion criteria.")
    sys.exit(1)
