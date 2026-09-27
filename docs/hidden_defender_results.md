# Hidden-defender RL: measured results and the finding that blocks the current framing

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

```bash
.venv/bin/python snort_validation/build_hidden_defender_corpus.py
.venv/bin/python -m pytest tests/test_hidden_defender_env.py -q      # 12 passed
.venv/bin/python snort_validation/baseline_hidden_defender.py
.venv/bin/python ai_agent/train_hidden_defender_ppo.py
.venv/bin/python snort_validation/eval_all_real_snort.py             # real snort
.venv/bin/python snort_validation/semantics_strict_test.py
```
