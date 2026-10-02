# C2 Evasion RL

**English** · [Tiếng Việt](README.vi.md)

An RL red-team agent that mutates real C2 beacon packets to **evade Snort 2.9.20 (ET
Open C2 ruleset)** while the traffic still behaves like working C2. Every headline result
is scored by the real Snort binary.

**Headline:** 16/16 held-out flows evaded real Snort, against a negative control where the
unmutated traffic alerts 16/16.

---

## Layout

- `ai_agent/` — the agent. `hidden_defender_env.py` is the environment: 14 packet mutations,
  action masking, C2-semantics check. `train_hidden_defender_ppo.py` trains.
  `eval_masked_ppo_test.py` evaluates a checkpoint.
- `snort_validation/` — real Snort integration: rules, replica scorer, harness, audit scripts.
- `controls/` — correctness controls (negative control, surrogate-vs-Snort audit).
- `data/`, `snort_validation/pcaps/` — capture pool. `models/` — checkpoints.
  `snort_validation/reports/` — all JSON results.

The current system is the 14-mechanism `HiddenDefenderEnv` trained with MaskablePPO. The
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

### 1. Train (fast surrogate)

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/train_hidden_defender_ppo.py
```

MaskablePPO, 64 flows, stops at ≥90% valid evasion. → `reports/ppo_hidden_defender.json`.
Got 95.3% (61/64) @ 704 queries / 11 epochs.

### 2. Train scored by real Snort

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/train_hidden_defender_ppo.py --real-snort
```

~1.3 s/flow → ~2 h. Got 90.6% (58/64) @ 640 queries / 10 epochs.

### 3. Evaluate a checkpoint on held-out flows (the headline)

```bash
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/eval_masked_ppo_test.py --real-snort
```

16/16 valid evasions (100%) under real Snort. Policy used exactly two mechanisms:
`split8` (UDP) and `http_header_pad` (HTTP). → `reports/ppo_masked_test.json`.

### 4. Controls and surrogate audit

```bash
# negative control: unmutated C2 must alert
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/control_noop_real_snort.py     # -> 16/16 alerted

# surrogate vs real Snort, flow by flow
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/surrogate_vs_real_snort.py     # -> 8/8 agree

# 14 mechanisms x 16 flows against real Snort
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 \
  controls/surrogate_sweep_14mech.py      # -> 161/224 agree, 0 false-safe
```

### 5. Tests

```bash
.venv/bin/python3 -m pytest tests/ -q
```

## Train flags

`--real-snort` (score with the real binary) · `--n-flows N` (default 64) ·
`--max-epochs N` (default 40) · `--seed N` (default 42) · `--out PATH`.

## Honest caveats

- **Training and eval use different scorers.** The fast surrogate trains; the headline 16/16
  is measured by real Snort. The surrogate over-alerts, so its ~95% train number is not the
  same quantity as the real-Snort train number (90.6%, which also stopped at the 90%
  threshold — neither is a converged, multi-seed ceiling).
- **The surrogate drops 20.6% of real rules** (`pcre`, `byte_test`, `byte_extract`,
  `byte_jump`). It happens not to matter for this corpus (only 3 sids fire per capture) but
  would on other traffic.
- **n is small** (64 train / 16 test, single seed).

## Docs

`docs/surrogate_vs_reality_audit.md` — full surrogate-vs-Snort audit (224 real Snort calls).
`docs/RESULTS_PRESENTATION.md` — how every headline number is produced and verified.

## References

[Stratosphere / CTU-13](https://www.stratosphereips.org/datasets-ctu13) ·
[ET Open rules](https://rules.emergingthreats.net/open/) · [Snort 2.9](https://www.snort.org/) ·
[Stable-Baselines3](https://stable-baselines3.readthedocs.io/) ·
[Gymnasium](https://gymnasium.farama.org/)
