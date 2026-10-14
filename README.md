# C2 Evasion RL

**English** · [Tiếng Việt](README.vi.md)

An RL red-team agent that mutates real C2 beacon packets to **evade Snort 2.9.20 (ET
Open C2 ruleset)** while the traffic still behaves like working C2. Every number in the
results tables below was produced by the real Snort binary.

**Headline:** on 40 held-out flows the policy evades real Snort on **16/40 (40,0%)**, against
a negative control where the unmutated traffic alerts **40/40**. The 16 flows it evades are
exactly the 16 C2-beacon flows in the split — on C2 traffic alone that is **16/16 (100%)**.

---

## Read this first: what the test split actually contains

The 40 held-out flows are **not** 40 C2 beacons.

| group | capture | SID that fires | classtype | flows |
|---|---|---|---|---:|
| **c2-http** | `botnet-capture-20110811-neris` | 2012627, 2018983, 2039514, 2042945 | `trojan-activity` | 16 (40,0%) |
| **p2p-dht** | `botnet-capture-20110819-bot` | 2008581, 2008583 | `policy-violation` | 24 (60,0%) |

The `p2p-dht` half is BitTorrent DHT, not C2: **194/194 UDP packets decode as Bencode KRPC**
(`ping` 26, `find_node` 52; `ping`→`{id}`, `find_node`→`{id, target}`) — BEP 5. Snort flags it
because ET Open carries `ET P2P BitTorrent DHT` rules, but it is peer-to-peer background
traffic. The train split has the same shape (455 C2 + 697 DHT = 1153 flows).

This matters for reading every result below: **no mutation evades a DHT flow** (0/24 for all
17 mechanisms), so the achievable ceiling on the full 40-flow split is bounded well below
100% regardless of the policy.

---

## Layout

- `ai_agent/` — the agent. `hidden_defender_env.py` is the environment: **17** packet
  mutations, action masking, C2-semantics check. `train_hidden_defender_ppo.py` trains.
  `eval_masked_ppo_test.py` evaluates a checkpoint.
- `snort_validation/` — real Snort integration: rules, replica scorer, harness, audit scripts.
- `controls/` — correctness controls and one-off probes (`probe_*.py`).
- `data/`, `snort_validation/pcaps/` — capture pool. `models/` — checkpoints.
  `snort_validation/reports/` — all JSON results.
- `thesis/` — the write-up (`main.tex`).

The current system is the 17-mechanism `HiddenDefenderEnv` trained with MaskablePPO. The
older bandit / continuous-packet-stage systems described in `docs/` are history.

## Setup

Repo-local `.venv` is the only interpreter with the right deps (system python3 has none;
running from a subdirectory breaks imports). Python 3.11.

```bash
cd /root/.hermes/c2-evasion-rl
python3.11 -m venv .venv
.venv/bin/pip install "torch==2.14.*+cpu" --index-url https://download.pytorch.org/whl/cpu
.venv/bin/pip install "numpy>=2.0" "pandas>=2.2" "scipy>=1.11" "scikit-learn>=1.4" \
    "pyarrow>=15.0" "joblib>=1.3" "xgboost>=2.0" "scapy==2.7.0" \
    "stable-baselines3==2.9.0" "sb3-contrib==2.9.0" "gymnasium==1.3.0" "pytest==9.1.1"
```

Snort must be installed for the real-scoring path (`snort -V` → 2.9.20 GRE). Conda users:
`conda env create -f environment.yml && conda activate rl_c2_evasion`.

`PYTHONPATH=ai_agent:snort_validation` is required on every command below.

## Run

### 1. Train

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/train_hidden_defender_ppo.py --real-snort --seed 42 --n-flows 64
```

`--real-snort` scores with the real binary (~1.3 s/flow). Drop the flag to train against the
fast surrogate instead. → `snort_validation/reports/train_post_p14_rs_s42.json`.

### 2. Evaluate a checkpoint on held-out flows (the headline)

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/eval_masked_ppo_test.py --real-snort --model /tmp/model_full_p16d_120ep
```

→ `snort_validation/reports/p16d_eval_real_snort.json`. ~15 min for 40 flows × 17 actions.

### 3. Mechanism sweep — the achievable ceiling

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/probe_mech_sweep_real_snort.py
```

All 17 mechanisms × 40 flows = 680 queries against the real binary (~47 s), reporting the
oracle (`best_single`) and the headroom over the policy. → `p17_mech_sweep_real_snort_d8.json`.

### 4. Controls

```bash
# negative control: unmutated C2 must alert, or the evasion number is vacuous
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/control_noop_real_snort.py      # -> 40/40 alerted

# surrogate vs real Snort, flow by flow
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/surrogate_vs_real_snort.py      # -> 8/8 agree

# the surrogate must reproduce a second engine too (100-cell matrix)
.venv/bin/python3 -m pytest tests/test_replica_matches_suricata.py -q   # -> 7 passed, 100/100 cells agree
```

### 5. Tests

```bash
.venv/bin/python3 -m pytest tests/ -q     # -> 383 passed, 1 skipped
```

## Train flags

`--real-snort` (score with the real binary) · `--n-flows N` (default 64) · `--max-epochs N`
(default 40) · `--seed N` (default 42) · `--out PATH` · `--split {train,test}` ·
`--corpus PATH` · `--capture NAME` · `--model-out PATH`.

## Results

All measured with the real Snort 2.9.20 binary, ET Open C2 ruleset, 40 held-out flows.

**Policy vs. ceiling**

| quantity | value | source |
|---|---:|---|
| policy evasion | **16/40 = 40,0%** | `p16d_eval_real_snort.json` |
| negative control (`noop`) | 40/40 alerted ✅ | `control_noop_real_snort.json` |
| oracle, best single mechanism | **23/40 = 57,5%** (`split_slow`) | `p17_mech_sweep_real_snort_d8.json` |
| headroom | **17,5 pp** | |
| policy on the C2 subset only | **16/16 = 100%** | `p17_evasion_by_framing.json` |
| train, real Snort, seed 42 | 48,4% (31/64) | `train_post_p14_rs_s42.json` |
| same 680 queries under Suricata 7.0.3 | **0/40 = 0,0%** | `p16d_mech_sweep_suricata.json` |

**Per-mechanism, real Snort** (`noop` must be 0)

| mechanism | evaded /40 | C2 /16 | DHT /24 | byte-preserving? |
|---|---:|---:|---:|---|
| `split_slow` | **23** | 16 | 7 | yes |
| `split8` / `split16` / `split24` | **16** | 16 | 0 | yes |
| `http_header_pad` | **16** | 16 | 0 | no |
| `http_header_case` | **16** | 16 | 0 | no |
| `reorder`, `ttl`, `overlap8`, `noop`, `query_param_prepend` | 0 | 0 | 0 | — |
| `prepend4/8/12`, `pad16`, `corrupt8`, `length_wrapper` | 0 | 0 | 0 | no (break semantics) |

The policy's histogram is `http_header_pad` ×16 + `noop` ×24 — it evades every C2 flow and
correctly does nothing on the 24 DHT flows, where nothing works.

## Honest caveats

- **The 40/40 headline in older revisions was wrong** and has been removed. It came from
  `ppo_masked_test.json`, scored before the fragment-reassembly model was corrected. The
  current evaluation runs the same 40 flows through the real binary and reports 16/40.
  `controls/verify_report_claims.py` still asserts the old 40/40 figures and is known-stale.
- **60% of the test split is P2P, not C2.** See the table at the top. Every "ceiling" number
  is bounded by this. The honest C2-only figure is 16/16.
- **Two action families work, by two independent mechanisms.** `split*` is byte-preserving
  and wins by defeating Snort's `frag3` reassembly; `http_header_pad` / `http_header_case`
  change bytes and win through the payload match instead. Under a strict byte-equality
  semantics gate the header actions score 0/16 and only `split*` survives — the 57,5% oracle
  is measured under the lenient gate the reward actually uses.
- **The reward gate is lenient by design.** Rewriting an HTTP header can never be
  byte-preserving, so requiring it would make `http_header_*` unreachable rather than wrong.
  `semantics_ok_reward` is the port the environment scores through (`hidden_defender_env.py`).
- **Training and evaluation use different scorers** unless `--real-snort` is passed. The
  surrogate trains; the headline is the real binary. Neither the 48,4% train figure nor the
  40,0% eval figure is a converged multi-seed ceiling.
- **Single seed, one capture pair, 40 test flows.** The test split is deliberately held at 40
  flows so every earlier evaluation and control stays comparable.
- **Suricata 7.0.3 evades nothing (0/40) on the same 680 queries.** The evasion is specific
  to Snort's `frag3` configuration, not a general IDS weakness.
- **The surrogate is a replica, not Snort.** It agrees with Suricata on 100/100 test cells
  and with Snort on the sampled control, but `frag3` session lifetime
  (Paxson & Shankar 2003, 60 s default) and anomaly rejection only became faithful in the
  latest commits — earlier surrogate numbers predate that fix.

## Docs

`docs/surrogate_vs_reality_audit.md` — full surrogate-vs-Snort audit.
`docs/RESULTS_PRESENTATION.md` — how every headline number is produced and verified.

## References

[Stratosphere / CTU-13](https://www.stratosphereips.org/datasets-ctu13) ·
[ET Open rules](https://rules.emergingthreats.net/open/) · [Snort 2.9](https://www.snort.org/) ·
[Stable-Baselines3](https://stable-baselines3.readthedocs.io/) ·
[Gymnasium](https://gymnasium.farama.org/) ·
[Paxson & Shankar, *Real-world detection of attacks through prefractured TCP* (2003)](https://www.usenix.org/legacy/events/sec03/tech/full_papers/paxson/paxson.pdf)
