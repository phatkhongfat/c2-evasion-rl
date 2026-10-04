# Hidden-defender RL: measured results and the finding that blocks the current framing

> **Note (updated Oct 2026):** This document was written for an earlier corpus (64 train / 16 test). The **current measured headline** is recorded under `snort_validation/reports/ppo_masked_test.json` (masked PPO, real Snort): **40/40 valid evasion**, negative control **40/40 alerted** (`controls/control_noop_real_snort.json`). Training surrogate numbers: **127/128 @ 896 queries / 7 epochs** (`snort_validation/reports/ppo_hidden_defender.json`, 128-flow train). Sections 1–7 below remain as the original historical snapshot; see §8 for the current measured state.

Date: 2026-09-27. All numbers below come from real executions, not estimates.
Defender = real `snort` binary with the ET Open C2 ruleset (21374 rules).

## 1. What was built

| file | role |
|---|---|
| `snort_validation/build_hidden_defender_corpus.py` | 80 Snort-detected flows, 64 train / 16 test, cached |
| `ai_agent/hidden_defender_env.py` | gym env, 12 mechanisms, 8 black-box obs features |
| `snort_validation/baseline_hidden_defender.py` | random sweep, greedy, supervised tree |
| `ai_agent/train_hidden_defender_ppo.py` | PPO, 11 epochs, 704 queries |
| `snort_validation/eval_all_real_snort.py` | re-scores the full 16x12 matrix with the binary |
| `snort_validation/semantics_strict_test.py` | per-datagram reassembly + strict semantics bar |

## 2. Headline result: PPO does not beat the baselines

TRAIN split, 64 flows, `RealRulesReplica` for speed (0.33 ms/flow):

| method | queries | evaded | pct |
|---|---:|---:|---:|
| random_sweep | 309 | 58/64 | 90.6% |
| greedy | **149** | 58/64 | 90.6% |
| supervised_tree (oracle ceiling) | 64 | 63/64 | 98.4% |
| **PPO** | **704** | 58/64 | 90.6% |

PPO spends **4.7x more queries than greedy for identical evasion**.

TEST split, 16 held-out flows, **real snort binary** per query:

| method | queries | evaded | pct |
|---|---:|---:|---:|
| random_sweep | 55 | 16/16 | 100% |
| greedy | 33 | 16/16 | 100% |
| supervised_tree | 16 | 16/16 | 100% |
| PPO | 16 | 16/16 | 100% |

## 3. Why: the optimal action is essentially constant

Real-snort matrix, 16 test flows, per mechanism:

| mechanism | flows solved |
|---|---:|
| **split8** | **16/16** |
| split16 | 14/16 |
| split24 | 14/16 |
| reorder | 3/16 |
| ttl | 2/16 |
| prepend4/8/12, pad16, corrupt8, overlap8 | 0/16 |

`split8` alone is a universal action. A contextual bandit needs the best action
to *vary per flow*; here it does not, so any method that tries `split8` first is
near-optimal and PPO's stochastic policy is pure added variance.

## 4. The earlier 100% result was an artifact, and is retracted

An earlier run reported **100% evasion for every method**. That number was wrong,
and the cause is a defect in the reward, not in the defender.

`semantics_intact` originally accepted a mutation when every original segment
was a *substring* of the mutated stream. `prepend` inserts junk in front of every
segment, so each original segment still appears while the reassembled stream no
longer begins with the C2 command. Measured on real traffic:

```
original   b'd1:ad2:id20:b${\x90=\xcb...'
prepend12  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d1:ad2:id20:b${\x90=\xcb...'
```

An HTTP request line at offset 12 is not an HTTP request. `prepend` was not
evading the IDS, it was deleting the C2 channel. The bar is now byte equality of
the reassembled stream, which is the only bar fragmentation preserves by
construction, and `prepend` drops to 0/16.

## 5. Hypotheses tested and rejected

- **`frag3 policy first` causes saturation.** Rejected: re-ran the offset sweep
  under `policy last` (how fragment inspection is normally deployed) and got
  byte-identical results. Configuration was not the cause.
- **Parameterising the offset restores a search problem.** Rejected: under
  `policy first`, split offset 8 evades 16/16 and all 15 prepend offsets evict
  16/16. The trivial action is optimal across the whole offset space, not just
  at a lucky setting.

## 6. What this means for the RL framing

The honest conclusion is negative for the current setup: **fragmentation against
a static ET Open C2 ruleset is not a contextual-bandit problem, because the
defender's `depth:8` + 8-byte pattern is defeated by one constant fragmentation
offset regardless of the flow.** There is no per-flow structure for PPO to
exploit, so RL cannot beat "try split8 first".

RL becomes a meaningful research question only when the defender is
**heterogeneous or adaptive**, so that the offset that wins differs per flow:

1. **Per-flow rule depth.** Give each flow a ruleset whose C2 rule has a
   different `depth`/`offset`. The required fragment offset then varies per flow
   and the bandit has a real signal to learn. This is a one-line ruleset
   generator and needs no new data.
2. **Adaptive defender.** Let the defender add a rule once a fragmentation
   pattern repeats, which is how a real IDS vendor responds. Turns the problem
   into a genuine two-player game.
3. **Mixed defenders.** Randomly assign each flow to one of several rulesets per
   episode, so a policy that overfits one depth fails on the next.

Option 1 is the cheapest and gives the cleanest ablation. The existing
corpus, env, baselines and PPO loop all carry over unchanged; only the score
function changes.

## 7. Reproduce

## 8. Current measured state (2026-10, after corpus refactor + retrain)

**Corpus:** `snort_validation/reports/hidden_defender_corpus.pkl` — 1153 train / 40 test (N_TEST=40 frozen; `split_flows` stratified). Train framing: 698 Neris / 455 HTTP.

**Training (surrogate):** `ppo_hidden_defender.json`
- n_flows=128, epochs=7, queries=896, evaded=127/128 (99.2%), semantics_breaks=0, scorer=surrogate (replica). Stopped at ≥90% target (early stopping). This matches the committed report.

**Headline (real Snort, masked PPO):** `ppo_masked_test.json`
- split=test, n_flows=40, scorer=real_snort, **valid_evasion=40/40 (100%)**, alerted=0, masked_actions_used=0.
- Actions: `split8=24`, `split24=16` (no `split16` used). Policy still concentrates on fragmentation.
- Per-flow semantics_ok=true for all, and alert=false.

**Negative control (real Snort, unmutated):** `controls/control_noop_real_snort.json`
- control=unmutated, n=40, split=test, **alerted=40/40** → PASS.

**Verifier:** `controls/verify_report_claims.py` → **54/54 checks passed** (uses invariants, not pinned literal training numbers).

**Notes vs historical (16-test):** The 16-flow test was the historical held-out set; the current test is **40 flows** frozen for comparability. The qualitative finding (optimal action near-constant under static ET Open depth) remains the same; the quantitative headline is now 40/40 with real Snort. The 20.6% surrogate rule coverage and 0 false-safe on audited sets remain caveats.

### Reproduce (current)
```bash
cd /root/.hermes/c2-evasion-rl
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 -m pytest tests/ -q   # 86 passed
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 ai_agent/eval_masked_ppo_test.py --real-snort
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 controls/control_noop_real_snort.py
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 controls/verify_report_claims.py
```
