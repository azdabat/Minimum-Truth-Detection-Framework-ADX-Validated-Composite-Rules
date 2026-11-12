#!/usr/bin/env python3
"""
kql_testkit.py  —  run a KQL rule against fixture rows without ingesting anything.

How it works (the "let-shadow" trick):
  In KQL, `let DeviceRegistryEvents = datatable(...)[...];` shadows the real table
  of that name for the rest of the query. So a test is ONE self-contained query:
  the fixture rows become datatables, pinned in front of the rule body, and the
  whole thing runs on any Kusto endpoint — your local kustainer or CI's — with no
  ingestion, no table creation, deterministic every time.

Every table the rule references is shadowed. Tables with fixture rows get the
rows; tables without get an empty-but-typed datatable, so the query always
resolves. Unknown columns a rule references are auto-added as null strings
(best effort) so you rarely hand-edit the schema.
"""
import json
import re
import urllib.request
import urllib.error

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# ---------------------------------------------------------------------------
# MDE schema registry.  (col, type) per table.  Generous superset of what
# composite rules touch; add a line here if a rule references a column we lack.
# A few non-standard columns some rules use (InitiatingProcessSigner, a bare
# AccountName on DeviceRegistryEvents) are included so those rules resolve.
# ---------------------------------------------------------------------------

_INIT = [
    ("InitiatingProcessAccountDomain", "string"), ("InitiatingProcessAccountName", "string"),
    ("InitiatingProcessAccountSid", "string"), ("InitiatingProcessAccountUpn", "string"),
    ("InitiatingProcessAccountObjectId", "string"),
    ("InitiatingProcessFileName", "string"), ("InitiatingProcessFolderPath", "string"),
    ("InitiatingProcessCommandLine", "string"),
    ("InitiatingProcessId", "int"), ("InitiatingProcessParentId", "int"),
    ("InitiatingProcessParentFileName", "string"),
    ("InitiatingProcessSHA1", "string"), ("InitiatingProcessSHA256", "string"),
    ("InitiatingProcessMD5", "string"),
    ("InitiatingProcessVersionInfoCompanyName", "string"),
    ("InitiatingProcessVersionInfoProductName", "string"),
    ("InitiatingProcessVersionInfoOriginalFileName", "string"),
    ("InitiatingProcessVersionInfoFileDescription", "string"),
    ("InitiatingProcessVersionInfoInternalFileName", "string"),
    ("InitiatingProcessIntegrityLevel", "string"), ("InitiatingProcessTokenElevation", "string"),
    ("InitiatingProcessCreationTime", "datetime"),
    ("InitiatingProcessSigner", "string"),  # non-standard; some rules use it
]
_DEV = [("Timestamp", "datetime"), ("DeviceId", "string"), ("DeviceName", "string"),
        ("ReportId", "long"), ("ActionType", "string")]

MDE_SCHEMA = {
    "DeviceProcessEvents": _DEV + _INIT + [
        ("FileName", "string"), ("FolderPath", "string"), ("ProcessId", "int"),
        ("ProcessCommandLine", "string"), ("ProcessCreationTime", "datetime"),
        ("ProcessIntegrityLevel", "string"), ("ProcessTokenElevation", "string"),
        ("AccountDomain", "string"), ("AccountName", "string"), ("AccountSid", "string"),
        ("AccountUpn", "string"), ("AccountObjectId", "string"),
        ("SHA1", "string"), ("SHA256", "string"), ("MD5", "string"),
        ("ProcessVersionInfoCompanyName", "string"), ("ProcessVersionInfoProductName", "string"),
        ("ProcessVersionInfoOriginalFileName", "string"), ("ProcessVersionInfoFileDescription", "string"),
    ],
    "DeviceRegistryEvents": _DEV + _INIT + [
        ("RegistryKey", "string"), ("RegistryValueName", "string"),
        ("RegistryValueData", "string"), ("RegistryValueType", "string"),
        ("PreviousRegistryKey", "string"), ("PreviousRegistryValueName", "string"),
        ("PreviousRegistryValueData", "string"),
        ("AccountName", "string"),  # non-standard; present in some rules
    ],
    "DeviceFileEvents": _DEV + _INIT + [
        ("FileName", "string"), ("FolderPath", "string"),
        ("SHA1", "string"), ("SHA256", "string"), ("MD5", "string"),
        ("FileOriginUrl", "string"), ("FileOriginReferrerUrl", "string"),
        ("RequestAccountName", "string"), ("RequestAccountDomain", "string"),
        ("ShareName", "string"), ("PreviousFileName", "string"),
    ],
    "DeviceNetworkEvents": _DEV + _INIT + [
        ("RemoteIP", "string"), ("RemotePort", "int"), ("RemoteUrl", "string"),
        ("RemoteIPType", "string"), ("LocalIP", "string"), ("LocalPort", "int"),
        ("LocalIPType", "string"), ("Protocol", "string"),
    ],
    "DeviceImageLoadEvents": _DEV + _INIT + [
        ("FileName", "string"), ("FolderPath", "string"),
        ("SHA1", "string"), ("SHA256", "string"), ("MD5", "string"),
    ],
    "DeviceLogonEvents": _DEV + _INIT + [
        ("LogonType", "string"), ("AccountDomain", "string"), ("AccountName", "string"),
        ("AccountSid", "string"), ("RemoteIP", "string"), ("RemotePort", "int"),
        ("RemoteDeviceName", "string"), ("IsLocalAdmin", "bool"),
    ],
    "DeviceFileCertificateInfo": [
        ("Timestamp", "datetime"), ("DeviceId", "string"), ("DeviceName", "string"),
        ("SHA1", "string"), ("IsSigned", "bool"), ("SignatureType", "string"),
        ("Signer", "string"), ("SignerHash", "string"), ("Issuer", "string"),
        ("IssuerHash", "string"), ("CertificateSerialNumber", "string"),
        ("IsTrusted", "bool"), ("IsRootSignerMicrosoft", "bool"), ("ReportId", "long"),
    ],
    "DeviceEvents": _DEV + _INIT + [
        ("FileName", "string"), ("FolderPath", "string"),
        ("SHA1", "string"), ("SHA256", "string"), ("MD5", "string"),
        ("RegistryKey", "string"), ("RegistryValueName", "string"), ("RegistryValueData", "string"),
        ("RemoteIP", "string"), ("RemotePort", "int"), ("RemoteUrl", "string"),
        ("LocalIP", "string"), ("LocalPort", "int"),
        ("AccountName", "string"), ("AccountDomain", "string"),
        ("AdditionalFields", "string"),
    ],
}

_NULL = {"string": '""', "datetime": "datetime(null)", "int": "int(null)",
         "long": "long(null)", "bool": "bool(null)", "real": "real(null)",
         "dynamic": "dynamic(null)"}


def _fmt(value, ktype):
    if value is None or value == "":
        return _NULL.get(ktype, '""')
    if ktype == "string":
        # strip binary/control chars (keep tab/newline/CR), emit a valid KQL literal
        return json.dumps(_CTRL.sub("", str(value)), ensure_ascii=False)
    if ktype == "datetime":
        return f"datetime({value})"
    if ktype in ("int", "long"):
        try:
            return str(int(value))
        except (TypeError, ValueError):
            return _NULL[ktype]
    if ktype == "real":
        try:
            return repr(float(value))
        except (TypeError, ValueError):
            return _NULL[ktype]
    if ktype == "bool":
        return "true" if str(value).lower() in ("true", "1") else "false"
    if ktype == "dynamic":
        return f"dynamic({json.dumps(value)})"
    return json.dumps(str(value))


def referenced_tables(rule_text):
    """Which known MDE tables does this rule mention?"""
    return [t for t in MDE_SCHEMA if re.search(rf"\b{re.escape(t)}\b", rule_text)]


def datatable_expr(table, rows, schema):
    """Just the datatable(...)[...] literal — reused by the test harness and the ADX ingester."""
    cols = schema[table]
    header = ", ".join(f"{c}:{t}" for c, t in cols)
    if not rows:
        return f"datatable({header}) []"
    body = ",\n".join("    " + ", ".join(_fmt(r.get(c), t) for c, t in cols) for r in rows)
    return f"datatable({header}) [\n{body}\n]"


def build_datatable(table, rows, schema):
    return f"let {table} = {datatable_expr(table, rows, schema)};"


def build_query(rule_text, fixtures, schema):
    """fixtures: {table: [rows]}.  Returns one self-contained query string."""
    tables = set(referenced_tables(rule_text)) | set(k for k in fixtures if k in schema)
    shadows = [build_datatable(t, fixtures.get(t, []), schema) for t in sorted(tables)]
    return "\n".join(shadows) + "\n" + rule_text


# ---------------------------------------------------------------------------
# kustainer REST client (v1 query endpoint; local emulator needs no auth)
# ---------------------------------------------------------------------------

_UNRESOLVED = [
    re.compile(r"resolve[^']*'([A-Za-z_][A-Za-z0-9_]*)'"),
    re.compile(r"'([A-Za-z_][A-Za-z0-9_]*)'\s+could not be resolved"),
]


def _post(cluster, db, csl, timeout=60):
    url = cluster.rstrip("/") + "/v1/rest/query"
    data = json.dumps({"db": db, "csl": csl}).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        msg = body
        try:
            j = json.loads(body)
            msg = (j.get("error", {}) or {}).get("@message") or j.get("error", {}).get("message") or body
        except json.JSONDecodeError:
            pass
        return None, msg
    except urllib.error.URLError as e:
        return None, f"connection error: {e} (is kustainer running at {cluster}?)"


def _rows_from_v1(payload):
    tbl = payload["Tables"][0]
    cols = [c["ColumnName"] for c in tbl["Columns"]]
    return [dict(zip(cols, r)) for r in tbl["Rows"]]


def run_rule(rule_text, fixtures, cluster="http://localhost:8080", db="NetDefaultDB",
             schema=None, max_heal=12):
    """Execute a rule against fixtures. Returns (rows, meta). Raises on hard error."""
    schema = {k: list(v) for k, v in (schema or MDE_SCHEMA).items()}
    healed = []
    for _ in range(max_heal + 1):
        query = build_query(rule_text, fixtures, schema)
        payload, err = _post(cluster, db, query)
        if payload is not None:
            return _rows_from_v1(payload), {"healed_columns": healed, "query": query}
        # try to auto-heal an unresolved-column error
        col = None
        for rx in _UNRESOLVED:
            m = rx.search(err or "")
            if m and m.group(1) not in MDE_SCHEMA:
                col = m.group(1)
                break
        if not col or col in healed:
            raise RuntimeError(err)
        healed.append(col)
        for t in referenced_tables(rule_text):
            if col not in [c for c, _ in schema[t]]:
                schema[t].append((col, "string"))
    raise RuntimeError(f"gave up after healing {healed}; last error stands")


# ---------------------------------------------------------------------------
# assertions
# ---------------------------------------------------------------------------

def _match(row, spec):
    """spec: {field: value | [allowed...] }. All fields must match."""
    for field, want in spec.items():
        have = row.get(field)
        allowed = want if isinstance(want, list) else [want]
        if not any(str(have) == str(a) for a in allowed):
            return False
    return True


def evaluate(rows, expect):
    """Return list of failure strings ([] == pass)."""
    fails = []
    n = len(rows)
    if expect.get("must_fire") and n == 0:
        fails.append("expected rule to fire (>=1 row) but got 0")
    if "min_rows" in expect and n < expect["min_rows"]:
        fails.append(f"min_rows {expect['min_rows']} but got {n}")
    if "max_rows" in expect and n > expect["max_rows"]:
        fails.append(f"max_rows {expect['max_rows']} but got {n}")
    if "row_count" in expect and n != expect["row_count"]:
        fails.append(f"row_count {expect['row_count']} but got {n}")
    for spec in expect.get("contains", []):
        if not any(_match(r, spec) for r in rows):
            fails.append(f"no row matched contains {spec}")
    for spec in expect.get("not_contains", []):
        if any(_match(r, spec) for r in rows):
            fails.append(f"a row matched forbidden {spec}")
    for col in expect.get("columns", []):
        if rows and col not in rows[0]:
            fails.append(f"expected output column '{col}' missing")
    return fails
