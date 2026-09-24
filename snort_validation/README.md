# Snort Validation Layer

This module validates RL agent evasion results against **Snort IDS** with botnet detection rules.

## Purpose

The main training pipeline uses an XGBoost surrogate judge (fast, ~1ms per flow). This validation layer adds a **real IDS check** to measure whether flows that bypass XGBoost would also bypass Snort.

**Key insight**: A high XGBoost evasion rate doesn't guarantee real-world evasion. Snort uses different detection logic (signature-based, protocol analysis) that may catch flows XGBoost misses.

## Architecture

```
Training Pipeline (unchanged)
  ↓
  PPO agent trains against XGBoost judge (~3 minutes)
  ↓
Validation Layer (runs after training)
  ↓
  1. run_evaluation.py: Run 80 episodes for agent/random/baseline policies
  2. validate_with_snort.py: Synthesize pcaps from mutated flows → Snort analysis
  3. Compare: XGBoost evasion rate vs Snort detection rate
```

**No impact on training** — Snort runs offline after training completes.

## Components

### 1. `flow_to_pcap.py`
Synthesizes pcap files from 6 flow features (dur, tot_pkts, tot_bytes, src_bytes, proto, state).

- TCP flows: SYN/SYN-ACK/ACK handshake + data packets + FIN
- UDP flows: simple request/response pattern
- ICMP flows: echo request/reply pairs

### 2. `run_evaluation.py`
Runs evaluation for three policies:
- **Agent**: Trained PPO policy (deterministic)
- **Random**: Random action baseline
- **Baseline**: No mutation (original flows)

Outputs: `snort_validation/reports/{agent,random,baseline}_evaluation.json`

Each JSON contains:
```json
{
  "policy": "agent",
  "num_episodes": 80,
  "xgb_evasion_rate": 0.89,
  "episodes": [
    {
      "episode_id": 0,
      "original_features": {...},
      "mutated_features": {...},
      "evaded_xgboost": true,
      "actions": [1, 2, 0, ...],
      ...
    },
    ...
  ]
}
```

### 3. `validate_with_snort.py`
For each episode:
1. Load mutated flow features
2. Synthesize pcap
3. Run `snort -r <pcap> -c snort.conf` with botnet rules
4. Count alerts → detection rate

Outputs: `snort_validation/reports/{agent,random,baseline}_snort_validation.json`

Summary report: `snort_validation_summary.json`

### 4. Snort Configuration

**Rules**: `rules/emerging-botcc.rules` (Emerging Threats botnet C&C rules, 57 signatures)

**Config**: `rules/snort.conf` (minimal config for offline pcap analysis)

## Usage

### Prerequisites

```bash
# Snort already installed via apt-get
which snort  # /usr/bin/snort

# Python dependencies (scapy)
pip install scapy
```

### Run Validation

```bash
# Step 1: Run evaluation (captures episode data)
cd /root/.hermes/c2-evasion-rl
python snort_validation/run_evaluation.py

# Output:
# - snort_validation/reports/agent_evaluation.json
# - snort_validation/reports/random_evaluation.json
# - snort_validation/reports/baseline_evaluation.json

# Step 2: Validate with Snort
python snort_validation/validate_with_snort.py

# Output:
# - snort_validation/reports/agent_snort_validation.json
# - snort_validation/reports/random_snort_validation.json
# - snort_validation/reports/baseline_snort_validation.json
# - snort_validation/reports/snort_validation_summary.json
```

### Expected Output

```
======================================================================
SNORT VALIDATION SUMMARY
======================================================================
Policy          XGBoost Evasion      Snort Detection      Snort Evasion
----------------------------------------------------------------------
Agent                  89.0%                 45.0%                55.0%
Random                 81.5%                 72.0%                28.0%
Baseline                0.0%                 90.4%                 9.6%
======================================================================
```

**Interpretation**:
- Agent bypasses XGBoost 89% but Snort still detects 45% → **real evasion rate ~55%**
- Gap between XGBoost and Snort evasion shows judge-reality mismatch
- Baseline (no mutation) shows Snort catches 90.4% of original botnet flows

## Baseline Comparison

| Policy   | XGBoost Evasion | Snort Detection | Snort Evasion | Interpretation |
|----------|-----------------|-----------------|---------------|----------------|
| Agent    | 89%             | 45%             | 55%           | Agent beats random by ~7% on XGBoost, ~27% on Snort evasion |
| Random   | 81.5%           | 72%             | 28%           | Random mutations fool XGBoost but not Snort |
| Baseline | 0%              | 90.4%           | 9.6%          | Original flows detected by both XGBoost and Snort |

**Key finding**: XGBoost is easier to fool than Snort. Agent learns patterns that work against the surrogate but don't generalize to signature-based IDS.

## Limitations

1. **Synthetic pcaps**: Flows reconstructed from metadata, not real packet payloads. Snort rules that inspect payload content may not fire.
2. **Limited ruleset**: Only botnet C&C rules (57 signatures). Full Snort deployment uses thousands of rules.
3. **Offline analysis**: No stateful tracking across multiple flows (Snort runs on one flow at a time).
4. **No payload obfuscation**: Agent only mutates flow-level features (timing, size, proto, state), not packet contents.

## Future Work

1. **Expand to packet-level actions**: Fragment, encrypt, encode payloads
2. **Multi-flow scenarios**: Evaluate agent on sustained C&C sessions
3. **Diverse rulesets**: Test against HTTP, DNS, TLS-specific rules
4. **Online IDS**: Integrate with live Snort/Suricata deployment

## Directory Structure

```
snort_validation/
├── flow_to_pcap.py           # Flow → pcap synthesis
├── run_evaluation.py          # Agent/random/baseline evaluation
├── validate_with_snort.py     # Snort validation runner
├── rules/
│   ├── snort.conf             # Minimal Snort config
│   └── emerging-botcc.rules   # Botnet detection rules
├── pcaps/                     # Temp pcaps (auto-cleaned)
└── reports/                   # JSON outputs
    ├── agent_evaluation.json
    ├── random_evaluation.json
    ├── baseline_evaluation.json
    ├── agent_snort_validation.json
    ├── random_snort_validation.json
    ├── baseline_snort_validation.json
    └── snort_validation_summary.json
```

## Verification

Test the flow→pcap synthesizer:

```bash
cd snort_validation
python flow_to_pcap.py  # Generates test_flow.pcap

# Inspect with tcpdump or Wireshark
tcpdump -r test_flow.pcap -n
```

Test Snort manually:

```bash
snort -c rules/snort.conf -r test_flow.pcap -A fast -q
```

## Notes

- Snort logs go to `snort_validation/pcaps/snort_logs/`
- Each episode's pcap is cleaned up after Snort runs (saves disk space)
- Validation takes ~5-10 seconds per episode (80 episodes ≈ 10-15 minutes total)
- XGBoost judge performance: ~1ms per flow (inference only)
- Snort performance: ~50-100ms per pcap (rule matching + protocol analysis)
