# Archive: Retired Code & Old Data

This directory contains code and data from earlier generations of the C2-evasion project that are no longer active.

## Contents

### `ai_agent/`
- `packet_level_env.py` — Packet-level RL environment (retired, superseded by flow-level hidden_defender_env)
- `packet_modifier.py` — Packet-level modification logic (retired)

### `snort_validation/`
- `build_hidden_defender_corpus.py` — Build script for corpus (one-time use)
- `eval_all_real_snort.py` — Legacy eval script
- `baseline_hidden_defender.py` — Legacy baseline computation
- `eval_surrogate_cross_validate.py` — Old cross-validation logic
- `capture_pool_sizes.py` — Pool size analysis (archived)
- `flow_to_pcap.py` — Flow-to-PCAP conversion (not needed for current system)
- `snort_query_service.py` — Deprecated Snort query service
- `snort_resident_service.py` — Deprecated resident service
- `semantics_strict_test.py` — Old semantics test suite
- `recost/` — Old cost-model experiment runs
- `feasibility/` — Old feasibility study data

### `tests/`
- `test_packet_level_env.py` — Tests for retired packet-level env
- `test_packet_modifier.py` — Tests for retired packet modifier
- `test_alert_id_independence.py` — Tests for old architecture
- `test_direction_2_masking.py` — Tests for directional flow handling
- `test_aggregate_inputs.py` — Tests for old aggregation

### `logs/`
- Old training logs from earlier generations (directional, enhanced, packet-level variants)

## Why Archive?

The current active system is **hidden-defender** (flow-level, MaskablePPO, real-time Snort scoring).
Earlier generations (packet-level, directional, bandit, etc.) remain in git history and are recoverable via:

```bash
git log --all --oneline -- archive/
git show <commit>:archive/<file>
```

Keeping the archive in the repo allows reviewers to understand the evolution and full context.
To recover a file: `git show <commit>:<path-in-archive> > <file>`
