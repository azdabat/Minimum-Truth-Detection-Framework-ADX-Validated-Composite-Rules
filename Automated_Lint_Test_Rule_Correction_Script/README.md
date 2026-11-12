## Static linting

Every rule is linted before it is tested. `tools/lint_kql.py` encodes the bug classes from the MTDF implementation review plus defects found by testing against real telemetry:

- dead registry anchors
- columns that don't exist in Defender
- stray semicolons
- prevalence windows that overlap the detection window
- unguarded null-SHA rarity, among others

ERROR findings fail the build.

```bash
python tools/lint_kql.py detections --no-port
```
