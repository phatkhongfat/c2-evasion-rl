# C2 Evasion RL — Demo Report

Static, offline-safe report UI. It reads all numbers from `snort_validation/reports/*.json` at runtime via `fetch()` (relative paths). No hardcoded metrics.

## Serving it

Do **not** use `python3 -m http.server --directory <repo>` on a public interface.
That serves the whole repository — `ai_agent/` source, the Snort ruleset, the
pickled corpus — to anyone who reaches the port.

Use the token-gated server instead, which serves only an allowlist of paths:

```bash
python3 /root/.hermes/scripts/demo_server.py     # :8899, token in /root/.hermes/demo-token.txt (0600)
```

It runs as the systemd user unit `hermes-demo.service`. Open it once with
`?token=<value from /root/.hermes/demo-token.txt>`; the server sets an HttpOnly
cookie so the page's `fetch()` calls authenticate. Source files and path
traversal 404 even with a valid token — the allowlist, not the token, is what
keeps the repository private.

- Files consumed: `hidden_defender_corpus.json`, `ppo_hidden_defender.json`, `ppo_masked_test.json`, `control_noop_real_snort.json`, `final_scale_up_summary.json`, `cross_capture_summary.json`, `surrogate_sweep_14mech.json`.
- Provenance: every KPI is traceable to the reports; verify with `controls/verify_report_claims.py` (81 checks — includes checks that `cross_capture_summary.json` agrees with every per-capture report, so a stale aggregate fails instead of being published).
- Toggle: light/dark, dense/comfy. Stats are tabular (not charts) to preserve literal numbers.