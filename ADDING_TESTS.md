# Detection tests

Every rule listed in `manifest.json` is tested on each push by the **Detection-as-Code Pipeline** (`.github/workflows/dac_pipeline.yml`):

1. **Lint** — `scripts/kql_linter.py` checks for corrupted files, unbalanced brackets, `any()` and `make_set(iff(...))`. Tested rules fail the build; every other rule gets warnings.
2. **Test** — `scripts/test_runner.py` starts the ADX emulator, loads each fixture as Defender-shaped tables (`schemas.json`), runs the rule and checks the result.

Each rule gets at least one **attack** fixture it must fire on and one **benign** fixture it must stay silent on.

**Known gaps.** A test with `"known_gap": true` describes an attack the rule *should* catch but doesn't yet. It shows as ⚠️ and never fails the build. When the rule is fixed it reports 🎉 *gap closed*. Remove the flag and it becomes a normal must-pass test. Blind spots stay documented instead of hidden.

## Add a test

1. Put a fixture in `fixtures/` — one list of rows per table, e.g. `{"DeviceProcessEvents": [ {...} ]}`. Timestamps can be any date; the runner shifts them to "10 minutes ago".
2. Copy an entry in `manifest.json`, point `rule` and `fixture` at your files, and set `expect` (`rows`, and any `first_row` values).
3. Run locally without the emulator to see the generated query: `python scripts/test_runner.py --dry-run`
