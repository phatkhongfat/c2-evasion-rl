# Defense-Aware C2 Evasion — Complete Change Log

**Project:** `/root/.hermes/c2-evasion-rl`
**Scope:** every change made from the moment Snort was introduced into the project
through the dataset/ruleset switch to Stratosphere IPS + ET Open C2.

This file is the single source of truth for *what changed*, *why*, and *what it
did to the model's measured results*. Read it top to bottom and you have the
whole story.

---

## 0. Executive summary

| Stage | XGBoost evasion | Snort detection | Notes |
|---|---|---|---|
| Blind agent (XGB-only reward) | **97.5%** | **71.2%** | evades the judge, walks into Snort |
| Random policy (reference) | 68.8% | 65.0% | sanity reference |
| No-mutation baseline | 10.0% | 11.2% | sanity reference |
| Defense-aware λ=5 | 92.5% | 91.2% | penalty too weak — worse than blind |
| Defense-aware λ=10 | 96.2% | 82.5% | evasion kept, Snort still high |
| Defense-aware λ=20 | 55.0% | **42.5%** | Snort down, evasion collapsed |

**Headline finding:** a surrogate trained on *reconstructed* features cannot
transfer. Moderate λ (5/10) produced agents that were *worse* at evading real
Snort than the blind agent, because the agent learned to exploit the
surrogate's blind spots rather than Snort's. This is why the project switched
to real Stratosphere/CTU-13 captures and real ET Open C2 rules.

---

## 1. Timeline of changes

### 1.1 Snort introduced: validation-only (no training influence)

| Change | File | Effect |
|---|---|---|
| Hand-written botnet rules | `snort_validation/rules/botnet-behavior.rules` | 61 rules, threshold-based |
| Aggressive variant for baselines | `snort_validation/rules/botnet-aggressive.rules` | 54 rules, low thresholds |
| Flow→pcap synthesis | `snort_validation/flow_to_pcap.py` | turns 6 aggregates into a pcap Snort can read |
| Snort validation harness | `snort_validation/validate_with_snort.py` | measures detection on agent episodes |
| Evaluation harness | `snort_validation/run_evaluation.py` | 80 episodes × 3 policies |

**Known defect found and fixed later:** `snort.conf` included
`emerging-botcc.rules`, a file that no longer exists in the repo. Snort exited
fatally on every run, so *all* detection rates silently read 0.0% — including
the unchanged baseline. Fixed by commenting the include; after the fix the
baseline read 10–15%, consistent with the original calibration.

### 1.2 Defense-aware reward shaping (the first real attempt)

| Change | File | Effect |
|---|---|---|
| Snort surrogate trainer | `snort_validation/train_snort_surrogate.py` | XGBoost classifier, features → P(Snort alert) |
| Surrogate artifact | `data/snort_surrogate.pkl` | AUC 0.997 on its own training distribution |
| Reward term | `ai_agent/c2_evasion_env.py` | `reward -= SNORT_PENALTY_SCALE * P(snort)` |
| Scale constant | `ai_agent/config.py` | `SNORT_PENALTY_SCALE = 20.0` |
| Opt-in training flag | `ai_agent/train_agent.py` | `--snort`, later `--snort-lambda` |
| Model naming | `ai_agent/train_agent.py` | `ppo_c2_evasion_agent_snortaware[_λ].zip` |

### 1.3 λ sweep (finding the trade-off)

Three retrains, each evaluated with XGBoost **and** real Snort. Results in the
executive table above. Two bugs surfaced and were fixed:

1. **Model filename bug.** SB3 2.9.0 appends `.zip` only when the path has no
   extension. The tag `_5.0` ends in `.0`, which pathlib reads as an
   extension, so the λ models were saved without `.zip` and every evaluation
   silently failed to load them (falling back to stale reports). Fixed by
   appending `.zip` explicitly.
2. **`run_evaluation.py` hard-coded the model path**, so a λ model could never
   be evaluated. Fixed with an `--agent-model` argument.

### 1.4 Feature engineering (derived features)

| Change | File | Effect |
|---|---|---|
| 20 candidate features | `ai_agent/flow_features.py` | derived from the 6 aggregates |
| Feature↔Snort validation | `snort_validation/validate_features_vs_snort.py` | correlation of each feature with Snort verdicts |
| Enhanced surrogate | `data/snort_surrogate_enhanced.pkl` | retrained on baseline + selected features |
| Enhanced data prep | `snort_validation/prepare_enhanced_surrogate_data.py` | assembles the training matrix |

**Critical limitation documented in `flow_features.py` itself:** the
"candidate features" are *reconstructed*, not measured. The parquet has no
packets, no timestamps and no flag counters, so packet-size distribution and
inter-arrival statistics are produced by a segmentation model
(`HDR_BYTES`/`MSS_TCP` assumptions). A surrogate trained on them learns the
reconstruction model — not the IDS's decision boundary. This is the direct
cause of the λ=5/λ=10 failure to transfer.

### 1.5 Dataset & ruleset switch (current stage)

| Change | File | Effect |
|---|---|---|
| ET Open fetch | `snort_validation/fetch_stratosphere.sh` | 1.9 GB CTU-13 archive from MCFP |
| Selective extraction | `snort_validation/extract_stratosphere.sh` | pcaps + binetflow only, no malware binaries |
| C2 ruleset builder | `snort_validation/build_et_open_c2_ruleset.py` | 21,374 real ET Open C2 rules |
| C2 ruleset | `snort_validation/et_open_c2/et_open_c2.rules` | 15 MB, third-party signatures |
| Build provenance | `snort_validation/et_open_c2/BUILD_REPORT.json` | per-file counts, exclusion reasons |
| Snort config | `snort_validation/et_open_c2/snort_et_c2.conf` | validates in 10 s |
| Real feature extractor | `snort_validation/extract_ctu13_real_features.py` | **47 measured features per flow** |
| Raw captures | `data/stratosphere/CTU-13-Dataset/` | 6 captures + labels (gitignored) |

---

## 2. Why the switch matters (evidence)

### 2.1 The old rules were circular

`botnet-behavior.rules` was written by inspecting the same flow aggregates the
features were derived from, and tuned to catch "70–80% of CTU-13 malicious
flows". A surrogate trained against it learns the rule thresholds the author
chose, not how a real IDS behaves. The CHANGELOG in this repo already flagged
this as a validity threat; the switch removes it.

### 2.2 The new rules are third-party

ET Open is an independent, widely deployed ruleset. Its C2-relevant subset:

| Source file | Rules included |
|---|---|
| `emerging-trojan.rules` | 19,064 |
| `emerging-mobile_malware.rules` | 1,144 |
| `emerging-malware.rules` | 624 |
| `emerging-retired.rules` | 231 |
| others (dns, p2p, exploit, …) | 311 |
| **total** | **21,374** |

Excluded, with reasons recorded in `BUILD_REPORT.json`:
* **652 rules from IP-blacklist files** (`emerging-botcc`, `emerging-ciarmy`,
  `emerging-compromised`, `emerging-dshield`, `threatview_CS_c2`). These match
  only on source/destination IP and can never fire on captured pcaps — they are
  the classic "blacklist, not signature" trap.
* **957 rules with no content match** (pure header/port matches) — too weak to
  constitute detection.
* **29,344 rules not C2-related** (web attacks, scans, policy, games, …).
* **36 rules with orphaned flowbits** — dropped so Snort starts cleanly.

### 2.3 Real traffic produces real alerts

A 120,000-packet slice of capture 1 (`botnet-capture-20110810-neris.pcap`)
through real Snort + the ET Open C2 subset:

```
94 alerts, including:
[1:2012533:6] ET TROJAN Win32/Virut.BN Checkin
  {TCP} 147.32.84.165:1044 -> 60.190.223.75:888
```

That is a genuine C2 checkin signature firing on genuine botnet traffic —
ground truth the previous hand-written rules could not provide.

---

## 3. Measured effects on the model

### 3.1 Reward shaping

The reward term is `reward -= λ · P(Snort alert)`, applied per step, opt-in
(default off, so existing models are bit-identical). λ=20 is below
`REWARD_EVASION = 50`, so evasion remains net-positive in principle — but at
λ=20 the expected penalty on the agent's preferred mutations exceeded the
evasion bonus, and the policy stopped evading at all (55% < random 68.8%).

### 3.2 The transfer failure (the important result)

| λ | XGB evasion | Snort detection | Verdict |
|---|---|---|---|
| 5 | 92.5% | 91.2% | worse at Snort than doing nothing clever |
| 10 | 96.2% | 82.5% | still worse than the blind agent's 71.2% |
| 20 | 55.0% | 42.5% | Snort beaten, evasion destroyed |

Non-monotonic in the wrong direction: *adding* defense awareness at moderate λ
made real-Snort evasion **worse**. Mechanism: the surrogate is a shadow model
trained on reconstructed features; the agent optimises against the shadow,
finds its errors, and those errors are precisely the mutations real Snort
catches. This is reward hacking of a stale surrogate, and it is the strongest
argument for measuring against real Snort and training on measured features.

---

## 4. Open items / next steps

1. **Finish real-feature extraction** across the 6 retained captures
   (`extract_ctu13_real_features.py --all`).
2. **Re-train the surrogate on measured features** and compare AUC against the
   reconstructed-feature surrogate on a held-out capture (cross-capture split,
   so the surrogate cannot memorise one botnet).
3. **Re-run the λ sweep** against the real-ET-Open surrogate.
4. **Report the honest comparison**, including the negative result if the
   transfer gap persists — that is a legitimate finding.

## 5. Reproduce

```bash
# ruleset
python snort_validation/build_et_open_c2_ruleset.py /tmp/etopen/rules
snort -c snort_validation/et_open_c2/snort_et_c2.conf -T        # ~10 s

# captures (1.9 GB, gitignored)
bash snort_validation/fetch_stratosphere.sh
bash snort_validation/extract_stratosphere.sh

# measured features
python snort_validation/extract_ctu13_real_features.py --all \
    --root data/stratosphere/CTU-13-Dataset \
    --out data/ctu13_real_features.parquet
```
