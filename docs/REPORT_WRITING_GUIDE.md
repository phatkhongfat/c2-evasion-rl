# Writing Guide: "Nghiên cứu và ứng dụng học tăng cường trong C2 Evasion"

**Target**: Research report for KMA cybersecurity program; 8 chapters, ~20–25 pages (EN); equivalent Vietnamese version.

**Active data sources** (all verified from the files below; read the figure from the file, never from this guide):
- `snort_validation/reports/ppo_masked_test_ALIGNED.json` — **current headline**: held-out 40-flow eval under the aligned strict semantics bar
- `snort_validation/reports/ppo_masked_test.json` — earlier eval (superseded)
- `snort_validation/reports/control_noop_real_snort.json` — control baseline (no mutation): **40/40 alerted = 100% detection, 0% evasion**
- `snort_validation/reports/hidden_defender_corpus.json` — corpus sizes (`n_train` 1153, `n_test` 40)
- `snort_validation/reports/surrogate_sweep_14mech.json` — per-mechanism real-Snort validity

**Key claim (current, honest)**: the MaskablePPO agent reaches **16/40 = 40.0% valid evasion** on the frozen held-out split against **real Snort 2.9.20 + ET Open**, versus a **no-mutation control at 0% evasion (40/40 alerted)**. "Valid" means `evaded and semantics_ok` under the strict byte-equality bar. The evasion is **framing-dependent**: 16/16 on the HTTP half, **0/24 on the neris half**.

**Do not quote the old 73.3% figure.** It came from a stale aggregated summary and was never reproduced by the honest pipeline. Superseded values and their replacements are in the table below.

| Superseded claim | Correct value | Source |
|---|---|---|
| mean evasion 73.3% (±10.8%) | **40.0%** (16/40) | `ppo_masked_test_ALIGNED.json` |
| control 71/71 | **40/40** | `control_noop_real_snort.json` |
| action space 65,536 | **14 actions** | `ACTION_NAMES` in `ai_agent/hidden_defender_env.py` |
| reward +100 / −2 / −50 | **+10 / −10 / −1** | `REWARD_EVADE` / `REWARD_BREAK_SEMANTICS` / `REWARD_ALERTED` |
| train split 1,113 | **1,153** | `hidden_defender_corpus.json` |

**Two bars that must never be conflated.** The training reward and the evaluation metric now share ONE rule: byte equality of the reassembled **client** stream (`snort_validation/c2_semantics.py`). Before this was fixed they diverged on 47/560 (flow, mechanism) pairs, which rewarded the policy for a mechanism the honest metric scored as zero. If you change one side, re-run `tests/test_semantics_bar_agreement.py`.

---

## Chapter Structure

### 1. Introduction & Motivation (1–2 pages)
**Goal**: Contextualize C2 evasion as a real security problem; motivate RL.

**Points**:
- Botnet C&C traffic detection is a cat-and-mouse game (static IDS rules vs obfuscation techniques)
- Manual evasion is labor-intensive; RL can automate payload/protocol mutation
- Existing work (cite if found): surrogate-based RL, but often offline or not validated on real IDS
- **This work**: Real-time RL on actual Snort 2.9.20; validates against **live detector**, not simulator

**Data to include**: None (motivational only).

---

### 2. Literature Review & Related Work (2–3 pages)
**Goal**: Position within adversarial ML and C2 evasion literature.

**Points**:
- Adversarial examples in ML (Carlini-Wagner, PGD, etc.) — motivate evasion as a search problem
- C2 detection: Snort IDS, Suricata, ET Open ruleset (static rules vulnerable to mutation)
- Prior C2 evasion work: DNS tunneling, encryption, protocol shimming (mostly manual/heuristic)
- RL for adversarial robustness: policy gradient, DQN, mask-based action spaces (e.g., RLlib, SB3)
- **Gap**: No prior work validates RL C2 evasion against **real Snort** with **honest cost accounting** (packet corruption = side-channel risk)

**Data to include**: None (literature only).

---

### 3. System Design & Threat Model (2–3 pages)
**Goal**: Define what the agent can and cannot do.

**Subsections**:

#### 3.1 Threat Model
- **Attacker**: Botnet operator with access to packet flow contents (plaintext C&C PDU)
- **Defender**: Static Snort rules (ET Open, no adaptive response)
- **Constraint**: Agent can corrupt **packet payloads** (TCP/UDP data), not metadata (IP/port). Per-flow action budget: **5 packets max**
- **Goal**: Maximize **undetected flows** while minimizing **packet corruptions** (side-channel noise)

#### 3.2 System Architecture
- **Environment**: Real pcap → Snort 2.9.20 scoring (no simulator)
- **State**: Flow header (5-tuple), packet sequence (truncated to 8 packets), alert history
- **Action space**: **14 discrete mechanisms** (`split8/16/24`, `prepend4/8/12`, `pad16`, `reorder`, `ttl`, `corrupt8`, `overlap8`, `noop`, `http_header_pad`, `length_wrapper`), filtered per flow by a **protocol-aware action mask** (feasibility filter, not a command interpreter). There is no 256×256 space.
- **Reward**: **+10** for `evaded and semantics_ok`; **−10** when the flow evades but breaks semantics; **−1** when Snort still alerts; minus the mechanism's action cost. A small protocol-appropriate bonus (+0.15) applies only when a valid evasion already happened.

**Data to include**: None (architectural).

---

### 4. Methodology (2–3 pages)
**Goal**: Explain training setup, corpus, and evaluation protocol.

#### 4.1 Training Data & Corpus Split
- **Source**: 3 botnet captures (stratosphere, cybersure-win)
- **Total flows**: 1153 flows
- **Train/test split**: **1153 total → 1113 train / 40 test** (stratified by capture to prevent memorization)
- **Policy training**: MaskablePPO, 8 parallel envs, 300K timesteps (~40 epochs over corpus)

**Data from report**:
- Total flows: **1153**
- Test set: **40**
- Train set: **1113**
- Framing split (train): **neris 698, http 455**

#### 4.2 Scoring & Validation
- **Real Snort scoring**: every (flow, mechanism) pair → its **own** pcap → Snort verdict. One pcap per flow (`batch_size=1`), never batched, so flows cannot suppress each other's alerts
- **Control baseline**: no mutation (noop) on the same 40 test flows → **40/40 alerted = 0% evasion**
- **Semantics bar**: strict byte equality of the reassembled **client** stream. A flow counts only when `evaded and semantics_ok`
- **Dynamic source identity**: each attempt gets a fresh source IP/port so Snort's `by_src` tracking cannot fire on repetition

**Data from control report**:
- Control baseline detected: **40/40 flows** (100% detection on no-mutation noop)
- Control evasion: **0%**

#### 4.3 Mechanism Cost Model
- **Evasion cost**: the mechanism's `ACTION_COSTS` entry, subtracted from the reward (bandwidth/disruption proxy)
- **Break-even**: `break_even_cost(n_corruptable) = EVASION_BONUS / n_corruptable` — the cost above which corrupting everything stops being optimal
- **Trade-off curve**: evasion % vs mechanism cost (document in results)

**Data to include**: the cost table from `ACTION_COSTS` in `ai_agent/hidden_defender_env.py` (values 0.0–0.60). Do **not** invent a "3.2 packets" figure — no report in this repo records packets-corrupted-per-flow; that number was fabricated in an earlier draft of this guide.

---

### 5. Results & Evaluation (3–4 pages)
**Goal**: Present key findings with evidence.

#### 5.1 Evasion Performance
**Main result table** (current headline: `ppo_masked_test_ALIGNED.json`):

| Metric | Value |
|--------|-------|
| Valid evasion (held-out) | **40.0%** (16/40) |
| HTTP half | **16/16 = 100%** (all `split24`) |
| neris half | **0/24 = 0%** (policy chose `noop`) |
| Semantics breaks | **0** |
| Control evasion (no mutation) | **0%** (40/40 alerted) |

**Figure 1**: per-flow valid-evasion outcome across the 40 held-out flows, split by framing.
**Figure 2**: mechanism validity by framing (see `surrogate_sweep_14mech.json`) — the two framings have almost disjoint viable mechanism sets.

**Data source**: `snort_validation/reports/ppo_masked_test_ALIGNED.json`
```json
{
  "valid_evasion": 16, "n_flows": 40, "valid_evasion_pct": 40.0,
  "baseline_alerted": 40, "baseline_alert_pct": 100.0,
  "per_framing": {"http": {"n": 16, "valid_evasion_pct": 100.0},
                  "neris": {"n": 24, "valid_evasion_pct": 0.0}}
}
```

**Historical runs — quote only with their provenance:**
| Run | Valid evasion | HTTP mechanism | neris mechanism |
|---|---|---|---|
| `ppo_masked_test_FIXED.json` | 57.5% | `split24` 16/16 | `split8` 7/24 |
| `ppo_masked_test_FIXED2.json` | 17.5% | `http_header_pad` 0/16 | `split8` 7/24 |
| `ppo_masked_test_ALIGNED.json` | **40.0%** | `split24` 16/16 | `noop` 0/24 |

The 57.5% run predates the semantics alignment, so its neris 7/24 was measured against a reward the honest metric contradicted. **Do not present 57.5% as the project's result.**

#### 5.2 Per-Flow Results
- **Valid evasions**: 16/40 (40.0%)
- **Alerted**: 24/40 — all 24 are neris flows the policy declined to mutate
- **HTTP**: every flow evaded with a valid command

**Data source**: `snort_validation/reports/ppo_masked_test_ALIGNED.json` (`per_flow`, 40 rows with `framing`, `action`, `alert`, `evaded`, `semantics_ok`, `valid_evasion`)

#### 5.3 Cost-Benefit Analysis
- **Mechanism cost is in the reward**, not in a packet-corruption count: report `ACTION_COSTS` per mechanism instead
- **The binding constraint is not cost — it is which mechanisms work per framing** (see 5.4)
- **Policy efficiency**: the agent avoided wasting mutations on flows where no available mechanism works

**Data source**: `snort_validation/reports/final_results_table.json` (sorted by evasion %)

#### 5.4 Limitations & Scope
- **Single botnet type validation**: 3 stratosphere/cybersure captures only (not generalizable to all botnet families)
- **Static rules only**: Snort ET Open ruleset; adaptive IDS (e.g., anomaly detectors) not tested
- **Offline learning**: Policy trained on corpus; real-time drift not modeled
- **Semantics assumption**: Assumes corrupted packets still parse as valid C&C (not always true)

**Key phrase**: "Results demonstrate evasion against **static ET Open on single-capture data**, not robust C2 evasion across all botnets."

---

### 6. Discussion (2–3 pages)
**Goal**: Interpret results and discuss implications.

#### 6.1 Why MaskablePPO Works Here
- **Action space is small but the choice is flow-dependent**: 14 mechanisms, and the mask makes some illegal per framing
- **Mask solves exploration**: Agent focuses on protocol-valid actions only (protocol-aware mutation constraints)
- **PPO's stability**: No off-policy divergence; sample-efficient on small corpus

#### 6.2 Cost Significance
- **3.2 corruptions mean**: Adding noise to C&C traffic (side-channel risk for attacker)
- **Tradeoff**: Evasion gain vs C&C reliability (mutated packets may cause botnet behavioral anomalies)
- **Practical implication**: Attacker must weigh evasion vs operational stability

#### 6.3 Comparison to Manual Evasion
- Manual techniques (e.g., DNS tunneling, encryption): Require protocol-specific domain knowledge
- **RL benefit**: Automatic search over mutation space; adapts to new rules (after retraining)
- **Limitation**: Requires IDS access for scoring (assumes white-box or replay environment)

#### 6.4 Generalization & Future Work
- **Generalization**: Train on larger corpus (MAWI, passive DNS) to test cross-family transfer
- **Adaptive defense**: Train defender using self-play or adversarial co-evolution
- **Semantic preservation**: Use reinforcement learning on semantic validators (not just binary detection)

---

### 7. Conclusion (1 page)
**Goal**: Summarize findings and reiterate scope.

**Key points**:
- Demonstrated that **MaskablePPO evades Snort** on real botnet captures — **but only on the HTTP half (16/16)**; on neris it does not, and the report must say so
- The binding constraint is **which mechanism is viable per framing**, not mechanism cost
- Approach is **honest about limitations**: validated on static rules, one botnet family, offline learning, and a training teacher (surrogate) that is nearly blind on the neris half
- **Future directions**: larger corpus, adaptive defenses, a training scorer that does not miss the neris alerts

**Final claim**: "This work shows RL can automate C2 evasion against static IDS, but **generalization and real-time deployment remain open challenges**."

---

### 8. Appendices (1–2 pages)

#### A. Corpus Statistics
- Flow counts per capture (table)
- Flow size distribution (histogram)
- Alert count per capture

**Data source**: `snort_validation/reports/cross_capture_summary.json`

#### B. Implementation Details
- MaskablePPO hyperparameters (learning rate, discount factor, entropy bonus)
- Snort configuration (rules version, detection mode)
- Training time (total compute hours)

#### C. Raw Results Table
- Full per-flow results (all 40 test flows with metrics)

**Data source**: `snort_validation/reports/final_results_table.json`

#### D. Negative Control & Semantics
- Document semantics check (how we validated corrupted packets are still valid C&C)
- Control noop results (all **40** flows detected, 0 evasion)

---

## Writing Order & Priorities

1. **Start with Section 5 (Results)** — most important; all data is ready
2. **Then Section 4 (Methodology)** — explain how you got those results
3. **Section 3 (System Design)** — define the problem precisely
4. **Section 6 (Discussion)** — interpret and compare
5. **Section 2 (Related Work)** — position your contribution
6. **Section 1 (Introduction)** — motivate from literature
7. **Section 7 (Conclusion)** — wrap up
8. **Appendices** — supporting details

---

## Key Numbers to Cite (each read from its source file, never from this table)

| What | Value | Source |
|------|-------|--------|
| Valid evasion (held-out) | **40.0%** (16/40) | ppo_masked_test_ALIGNED.json |
| HTTP half | 16/16 = 100% | ppo_masked_test_ALIGNED.json `per_framing` |
| neris half | 0/24 = 0% | ppo_masked_test_ALIGNED.json `per_framing` |
| Semantics breaks | 0 | ppo_masked_test_ALIGNED.json |
| Control baseline (noop) | **100% detected, 0% evasion** (40/40) | control_noop_real_snort.json |
| Test flows | 40 | hidden_defender_corpus.json `n_test` |
| Train flows | 1153 | hidden_defender_corpus.json `n_train` |
| Actions | 14 | ACTION_NAMES, ai_agent/hidden_defender_env.py |
| Reward | +10 / −10 / −1 | REWARD_* in ai_agent/hidden_defender_env.py |
| Observation | 11 dims (8 shallow + 3 framing) | OBS_DIM, ai_agent/hidden_defender_env.py |

**Numbers that must NOT appear in the report** (stale or fabricated): 73.3%, ±10.8%, 72.5%, 27.5%, 71/71, 65,536, +100/−2/−50, "3.2 packets corrupted", "mean 3.2".

---

## Visualizations to Create

1. **Figure 1**: per-flow outcome across the 40 held-out flows, grouped by framing (valid evasion / alerted)
2. **Figure 2**: mechanism validity by framing — shows the neris half has essentially one viable mechanism
3. **Figure 3**: learning curve (per-epoch valid rate over the 24 epochs of the aligned run)
4. **Figure 4**: the two-bar diagram — training reward semantics vs evaluation semantics, and the 47/560 pairs where they used to disagree
5. **Table 1**: Per-capture statistics (flows, alerts, baseline detected, evasion mean)

---

## Honesty Checklist

Before submission:
- [ ] Every claim backed by a number in `snort_validation/reports/`?
- [ ] Control baseline clearly stated (0% evasion on noop)?
- [ ] Scope clearly limited to "static ET Open, single-capture validation"?
- [ ] Semantics check explained (corrupted packets remain valid C&C)?
- [ ] Limitations section acknowledges generalization gaps?
- [ ] No hardcoded numbers — all fetched from live reports?

---

## File Locations for Reference

```
docs/RESULTS_PRESENTATION.md          # Main findings doc (60% overlap with Sections 5–6 here)
snort_validation/reports/
  ├── cross_capture_summary.json       # Mean metrics (PRIMARY for Sec 5.1)
  ├── ppo_masked_test.json             # Per-flow verdicts (PRIMARY for Sec 5.2)
  ├── control_noop_real_snort.json     # Control baseline (PRIMARY for Sec 5.4)
  └── final_results_table.json         # Ranked flows (SECONDARY for Sec 5.3)

ai_agent/
  ├── snort_bandit.py                  # Cost model (break_even_cost)
  └── train_hidden_defender_ppo.py     # Hyperparams (for Appendix B)

controls/verify_report_claims.py       # Verifier (109/109 checks pass)
```

---

## Language Notes (EN → VI)

When translating to Vietnamese (`thesis_vi.md`):
- Keep technical terms in English (MaskablePPO, Snort, ET Open, IDS)
- Translate concepts: "evasion" → "trốn tránh", "corruption" → "làm hỏng", "cost model" → "mô hình chi phí"
- Maintain all data points verbatim (numbers don't change)
- Structure and chapter order identical to English version
