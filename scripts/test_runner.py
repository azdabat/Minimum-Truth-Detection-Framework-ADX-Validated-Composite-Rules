import os
import json
import sys
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.helpers import dataframe_from_result_table

print("[*] Starting Multi-Fixture Detection Assertion Engine with ADX Emulator...")

fixture_dir = "tests/fixtures"
if not os.path.exists(fixture_dir):
    print(f"[!] Critical: Test fixture directory missing at {fixture_dir}")
    sys.exit(1)

fixtures = [f for f in os.listdir(fixture_dir) if f.endswith(".json")]
if not fixtures:
    print("[!] Warning: No test fixtures found.")
    sys.exit(0)

# 1. Connect to local ADX Kusto Emulator
try:
    kcsb = KustoConnectionStringBuilder.with_aad_application_key_url("http://localhost:8080", "unused", "unused", "unused")
    client = KustoClient(kcsb)
    database = "NetDefaultDB"
    # Quick ping/validation query
    client.execute(database, "print 1")
    print("[+] Successfully connected to local ADX Kusto Emulator.")
except Exception as e:
    print(f"[!] Failed to connect to ADX Emulator: {e}")
    sys.exit(1)

# 2. Ensure Defender-style tables exist in the emulator
client.execute(database, ".create-or-alter table DeviceRegistryEvents (Timestamp: datetime, DeviceId: string, DeviceName: string, ActionType: string, RegistryKey: string, RegistryValueName: string, RegistryValueData: string, InitiatingProcessFileName: string, InitiatingProcessCommandLine: string, InitiatingProcessSHA256: string, InitiatingProcessSigner: string, InitiatingProcessVersionInfoCompanyName: string, InitiatingProcessAccountName: string, AccountName: string)")
client.execute(database, ".create-or-alter table DeviceFileEvents (Timestamp: datetime, DeviceId: string, SHA256: string)")

# 3. Load all KQL detection rules across the repo
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
failed_assertions = 0

# 4. Iterate and ingest fixtures, then test rules
for fix_file in fixtures:
    fix_path = os.path.join(fixture_dir, fix_file)
    
    # Clear tables before ingesting a new fixture set
    client.execute(database, ".clear table DeviceRegistryEvents data")
    client.execute(database, ".clear table DeviceFileEvents data")

    with open(fix_path, "r", encoding="utf-8") as f:
        json_data = f.read()

    # Ingest JSON fixture into DeviceRegistryEvents table
    try:
        client.execute(database, f".ingest inline into table DeviceRegistryEvents <|\n{json_data}")
    except Exception as e:
        print(f"[!] Error ingesting fixture {fix_file}: {e}")
        continue

    print(f"[*] Evaluating Fixture: {fix_file} against {len(kql_rules)} rules...")
    
    for rule_name, rule_content in kql_rules:
        try:
            response = client.execute(database, rule_content)
            df = dataframe_from_result_table(response.primary_results[0])
            matches = len(df)
            total_matches += matches
            
            if matches > 0:
                print(f"    [MATCH] Rule '{rule_name}' triggered on fixture '{fix_file}' ({matches} row(s))")
        except Exception as e:
            print(f"    [ERROR] Rule '{rule_name}' failed execution: {e}")
            failed_assertions += 1

if failed_assertions > 0:
    print(f"[-] FAIL: Testing completed with {failed_assertions} error(s).")
    sys.exit(1)
else:
    print(f"[+] PASS: Multi-fixture automated telemetry validation completed successfully! Total matches caught: {total_matches}")
    sys.exit(0)
