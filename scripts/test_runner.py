#!/usr/bin/env python3
"""
MTDF Detection-as-Code test runner.

For every test in tests/manifest.json:
  1. Load the rule (.kql / .KQL) and its telemetry fixture (JSON, one list of rows per table).
  2. Shift fixture timestamps so the newest event is 10 minutes old (rules use ago()).
  3. Turn each table the rule references into an inline `datatable` with Defender-shaped
     columns from tests/schemas.json. Tables with no fixture rows are created empty.
  4. Run "<inline tables> + <rule>" against the local ADX emulator (Kustainer).
  5. Compare the result to the expected row count and column values.

Nothing is ingested, so tests cannot leak into each other.

Usage:
  python scripts/test_runner.py            # run against the emulator at http://localhost:8080
  python scripts/test_runner.py --dry-run  # print the generated queries only (no emulator needed)
"""
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "tests", "manifest.json")
SCHEMAS = os.path.join(ROOT, "tests", "schemas.json")
CLUSTER = os.environ.get("KUSTO_URL", "http://localhost:8080")
DATABASE = "NetDefaultDB"
DRY_RUN = "--dry-run" in sys.argv


def annotate(level, msg, path=None):
    """Print a GitHub Actions annotation (shows up on the run page) and a plain line."""
    if os.environ.get("GITHUB_ACTIONS"):
        loc = f" file={path}" if path else ""
        print(f"::{level}{loc}::{msg}")
    else:
        print(f"[{level.upper()}] {msg}")


def parse_ts(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)


def kql_literal(value, ctype):
    """Render one Python value as a KQL literal of the given column type."""
    if value is None:
        return '""' if ctype == "string" else f"{ctype}(null)"
    if ctype == "string":
        clean = "".join(ch for ch in str(value) if ch >= " " or ch in "\t")
        return json.dumps(clean, ensure_ascii=False)
    if ctype == "datetime":
        return f"datetime({value.strftime('%Y-%m-%dT%H:%M:%S.%f')}Z)"
    if ctype in ("long", "int"):
        return f"{ctype}({int(value)})"
    if ctype in ("real", "double"):
        return f"real({float(value)})"
    if ctype == "bool":
        return "true" if value else "false"
    if ctype == "dynamic":
        return f"dynamic({json.dumps(value)})"
    raise ValueError(f"Unsupported column type '{ctype}'")


def build_query(rule_text, fixture, schemas):
    """Prefix the rule with inline datatables that stand in for the Defender tables it uses."""
    tables = {k: v for k, v in fixture.items() if not k.startswith("_")}
    unknown = [t for t in tables if t not in schemas]
    if unknown:
        raise ValueError(f"Fixture uses tables not in tests/schemas.json: {unknown}")

    # Shift every datetime so the newest fixture event is 10 minutes old.
    stamps = [parse_ts(r["Timestamp"]) for rows in tables.values() for r in rows if r.get("Timestamp")]
    shift = (datetime.now(timezone.utc) - timedelta(minutes=10) - max(stamps)) if stamps else timedelta(0)

    referenced = [t for t in schemas if not t.startswith("_") and re.search(rf"\b{t}\b", rule_text)]
    lets = []
    for table in referenced:
        schema = schemas[table]
        rows = tables.get(table, [])
        values = []
        for row in rows:
            extra = [c for c in row if c not in schema]
            if extra:
                raise ValueError(f"{table}: fixture columns not in schema {extra} — add them to tests/schemas.json if they exist in Defender")
            for col, ctype in schema.items():
                v = row.get(col)
                if ctype == "datetime" and v is not None:
                    v = parse_ts(v) + shift
                values.append(kql_literal(v, ctype))
        cols = ", ".join(f"{c}:{t}" for c, t in schema.items())
        body = ",\n    ".join(", ".join(values[i:i + len(schema)]) for i in range(0, len(values), len(schema)))
        lets.append(f"let {table} = datatable({cols})[\n    {body}\n];")
    return "\n".join(lets) + "\n" + rule_text


def check(expect, rows):
    """Return a list of human-readable failures (empty list = pass)."""
    problems = []
    if "rows" in expect and len(rows) != expect["rows"]:
        problems.append(f"expected {expect['rows']} row(s), got {len(rows)}")
    if expect.get("first_row"):
        if not rows:
            problems.append("expected a first row but the rule returned nothing")
        else:
            first = rows[0]
            for col, want in expect["first_row"].items():
                if col not in first:
                    problems.append(f"column '{col}' missing from output")
                    continue
                got = first[col]
                same = (float(got) == float(want)) if isinstance(want, (int, float)) and got is not None else (got == want)
                if not same:
                    problems.append(f"{col}: expected {want!r}, got {got!r}")
    return problems


def connect():
    from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
    client = KustoClient(KustoConnectionStringBuilder.with_no_authentication(CLUSTER))
    deadline = time.time() + 300
    while True:
        try:
            client.execute(DATABASE, "print 1")
            print(f"[+] ADX emulator is up at {CLUSTER}")
            return client
        except Exception as exc:  # emulator still starting
            if time.time() > deadline:
                annotate("error", f"ADX emulator did not become ready within 5 minutes: {exc}")
                sys.exit(1)
            print("[*] Waiting for ADX emulator to start...")
            time.sleep(10)


def main():
    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    schemas = json.load(open(SCHEMAS, encoding="utf-8"))
    tests = manifest.get("tests", [])
    print(f"[*] MTDF test runner — {len(tests)} test(s){' (dry run)' if DRY_RUN else ''}")

    client = None if DRY_RUN else connect()
    results = []

    for t in tests:
        rule_path = os.path.join(ROOT, t["rule"])
        label = f"{t['id']} — {t['name']}"
        try:
            raw = open(rule_path, "rb").read()
            if raw.count(b"\x00"):
                raise ValueError("rule file contains null bytes (corrupted upload)")
            rule_text = raw.decode("utf-8-sig")
            fixture = json.load(open(os.path.join(ROOT, t["fixture"]), encoding="utf-8"))
            query = build_query(rule_text, fixture, schemas)
        except Exception as exc:
            annotate("error", f"{label}: could not build test — {exc}", t["rule"])
            results.append((t, False, [str(exc)], 0))
            continue

        if DRY_RUN:
            print(f"\n===== {label} =====\n{query[:3000]}{'...' if len(query) > 3000 else ''}")
            continue

        try:
            response = client.execute(DATABASE, query)
            rows = response.primary_results[0].to_dict()["data"]
        except Exception as exc:
            msg = str(exc).splitlines()[0][:400]
            annotate("error", f"{label}: query failed — {msg}", t["rule"])
            results.append((t, False, [f"query failed: {msg}"], 0))
            continue

        problems = check(t.get("expect", {}), rows)
        ok = not problems
        print(f"[{'PASS' if ok else 'FAIL'}] {label} — {len(rows)} row(s)")
        if rows:
            print("       first row: " + json.dumps({k: rows[0][k] for k in list(rows[0])[:8]}, default=str))
        for p in problems:
            annotate("error", f"{label}: {p}", t["rule"])
        results.append((t, ok, problems, len(rows)))

    if DRY_RUN:
        return 0

    passed = sum(1 for r in results if r[1])
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"## MTDF detection tests — {passed}/{len(results)} passed\n\n")
            fh.write("| Test | Rule | Rows | Result |\n|---|---|---|---|\n")
            for t, ok, problems, n in results:
                verdict = "✅ pass" if ok else "❌ " + "; ".join(problems)
                fh.write(f"| {t['id']} — {t['name']} | `{os.path.basename(t['rule'])}` | {n} | {verdict} |\n")

    print(f"\n[*] {passed}/{len(results)} test(s) passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
