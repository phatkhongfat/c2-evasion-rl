# C2 Evasion RL — Demo Report

Static, offline-safe report UI. It reads all numbers from `snort_validation/reports/*.json` at runtime via `fetch()` (relative paths). No hardcoded metrics.

- Open: `http://127.0.0.1:8899/demo/index.html` (local) or serve repo root and browse `/demo/`.
- Files consumed: `hidden_defender_corpus.json`, `ppo_hidden_defender.json`, `ppo_masked_test.json`, `control_noop_real_snort.json`, `final_scale_up_summary.json`, `cross_capture_summary.json`, `surrogate_sweep_14mech.json`.
- Provenance: every KPI is traceable to the reports; verify with `controls/verify_report_claims.py` (54/54).
- Toggle: light/dark, dense/comfy. Stats are tabular (not charts) to preserve literal numbers.