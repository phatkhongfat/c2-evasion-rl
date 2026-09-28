# Three Directions to Enable RL Learning: Implementation Plan

---

## Direction 1: Action Cost Penalty (Easiest)

**Goal**: Differentiate mechanisms by computational cost, forcing RL to learn trade-offs instead of always picking the highest-evasion action.

**Rationale**: 
- In real networks, fragmentation (split) consumes bandwidth, CPU, and raises suspicion
- HTTP header padding is stealthy (legitimate traffic often has custom headers)
- RL should learn: "Split only when necessary; prefer padding on HTTP flows"

**Implementation**:

### Step 1.1: Modify Reward Function
**File**: `ai_agent/hidden_defender_env.py`

Add action costs dict:
```python
ACTION_COSTS = {
    0: 0.0,      # noop
    1: 0.5,      # split8 (highest cost — many fragments)
    2: 0.4,      # split16
    3: 0.3,      # split24 (lowest split cost)
    4: 0.2,      # prepend4
    5: 0.2,      # prepend8
    6: 0.2,      # prepend12
    7: 0.05,     # http_header_pad (cheap, natural)
    8: 0.25,     # length_wrapper (medium cost)
    9: 0.35,     # reorder (out-of-order penalty)
    10: 0.1,     # ttl (low cost, but unreliable)
    11: 0.4,     # corrupt (high risk of detection)
    12: 0.35,    # overlap (ambiguity cost)
    13: 0.1,     # pad_payload (append, low cost)
}

def step(self, action):
    ...
    evasion_success = verdict  # True if Snort didn't alert
    action_cost = ACTION_COSTS[action]
    
    # New reward: success bonus minus action cost
    reward = (1.0 if evasion_success else 0.0) - action_cost
    
    return obs, reward, done, info
```

### Step 1.2: Test on HTTP-only corpus
**Goal**: Verify RL now prefers `http_header_pad` (cost 0.05, evade 100%) over `split24` (cost 0.3, evade 100%).

**Expected behavior**:
- Greedy (no cost) → split24
- RL with cost → http_header_pad on HTTP, forced to split24 on Neris
- **Net evasion rate**: still ~90.6% (same mechanisms work), but **policy now differentiates by cost**

### Step 1.3: Evaluate full 16-flow corpus
**File**: Create `snort_validation/eval_action_cost_comparison.py`

Compare:
```
Mechanism | HTTP flows | Neris flows | Cost | Total reward
----------|------------|-------------|------|---------------
Greedy    | split24    | split24     | N/A  | 16 × 1.0 = 16.0
RL+cost   | http_header_pad (net 15.95) | split24 (net 15.7) | — | 31.65
```

**Deliverable**: Report `reports/action_cost_comparison.json`

### Step 1.4: Train PPO with cost penalty
**File**: Modify `ai_agent/train_hidden_defender_ppo.py`

- Train for 100k steps (same as before)
- Log average reward per episode (should be lower than no-cost baseline, but policy more diverse)
- Save final policy

**Expected result**: RL learns action differentiation → policy chooses cheaper actions when evade success is equal

---

## Direction 2: Fix Snort Reassembly (Most Technically Sound)

**Goal**: Enable Snort to reassemble fragmented packets before rule matching, making fragmentation-based evasion fail.

**Rationale**: 
- Our current Snort config may not have `frag3` or `stream5` preprocessors active
- Real Snort should reassemble before detection — if split24 evades 100%, the config is wrong
- This is the "correct" defender setup

**Investigation Phase**:

### Step 2.1: Inspect current Snort config
**File**: Check `/root/.hermes/c2-evasion-rl/snort_validation/et_open_c2/snort_et_c2.conf`

```bash
grep -E "^(preprocessor|config)" snort_validation/et_open_c2/snort_et_c2.conf | head -20
```

**Expected**: Look for lines like:
- `preprocessor frag3: ...` (IP fragmentation reassembly)
- `preprocessor stream5: ...` (TCP stream reassembly)

If missing or commented out, they are disabled.

### Step 2.2: Test reassembly with a reference IDS
**Goal**: Verify that fragmentation should fail against a properly-configured IDS.

**File**: Create `snort_validation/test_snort_reassembly.py`

```python
import subprocess
import tempfile
from scapy.all import Ether, IP, TCP, ICMP, Raw
from snort_batch_service import SnortBatchService

# Create a test packet: split24 + fragmentation of C2 GET request
original_payload = b"GET /index.php?a=1&b=2 HTTP/1.1\r\nHost: evil.com\r\n\r\n"
frag1 = Ether()/IP(dst="192.168.1.1", flags="MF", frag=0)/TCP(dport=443)/Raw(load=original_payload[:24])
frag2 = Ether()/IP(dst="192.168.1.1", frag=1)/TCP(dport=443)/Raw(load=original_payload[24:])

# Test against current config
service = SnortBatchService(conf_path="snort_validation/et_open_c2/snort_et_c2.conf")
verdict_before = service.query([frag1, frag2])
print(f"Snort verdict on fragmented C2 (current config): {verdict_before}")

# If verdict_before == False (no alert), reassembly is disabled
# Enable frag3 and retest
```

### Step 2.3: Enable/fix Snort preprocessors
**File**: Modify `snort_validation/et_open_c2/snort_et_c2.conf`

Ensure these lines are active (uncommented):
```
preprocessor frag3: policy first, overlap_limit 10, min_fragment_length 100, timeout 180
preprocessor stream5: policy balanced, timeout 180, max_tcp_sessions 262144
```

### Step 2.4: Re-evaluate with fixed config
**File**: Rerun `snort_validation/eval_all_real_snort.py`

**Expected outcome**:
```
Before fix: split24 = 16/16 evade (100%)
After fix:  split24 = 0/16 evade (0%)
            http_header_pad = 8/8 evade (100%) on HTTP
            Neris flows = forced to find alternatives
```

### Step 2.5: Train RL on "fixed defender" environment
**File**: Create `ai_agent/train_hidden_defender_ppo_fixed_snort.py`

- Point to fixed Snort config
- Train PPO for 100k steps
- Log whether RL discovers new mechanisms (reorder, overlap, etc.)

**Deliverable**: Report `reports/fixed_snort_rl_results.json` + comparison table

---

## Direction 3: Heterogeneous Defender (Most Research-Valuable)

**Goal**: Create 3–5 different Snort configurations, each with different rule coverage gaps. RL must learn to probe and adapt per configuration.

**Rationale**:
- Real-world IDS deployments vary widely
- RL can learn a policy that generalizes across multiple defender configurations
- This becomes a POMDP (Partially Observable MDP) — classical RL research problem

**Implementation**:

### Step 3.1: Design 5 Snort configurations
**File**: Create `snort_validation/defender_profiles.yaml`

```yaml
defenders:
  A:
    name: "frag3_only"
    description: "Reassembles fragments, misses padding"
    enabled_preprocessors: [frag3, stream5]
    disabled_rules: [rule_ids_for_http_header_pad]  # Miss padding checks
    
  B:
    name: "pad_detector_only"
    description: "Detects padding, misses fragmentation reassembly"
    enabled_preprocessors: [stream5]  # No frag3
    disabled_rules: []
    
  C:
    name: "reorder_aware"
    description: "Detects out-of-order segments, allows split"
    enabled_preprocessors: [frag3, stream5_reorder_policy_strict]
    disabled_rules: []
    
  D:
    name: "minimal_config"
    description: "Only basic rules, no preprocessors"
    enabled_preprocessors: []
    disabled_rules: [all_preprocessor_dependent_rules]
    
  E:
    name: "strict_full_config"
    description: "All preprocessors + all rules active"
    enabled_preprocessors: [frag3, stream5, paf]
    disabled_rules: []
```

### Step 3.2: Create defender config generator
**File**: Create `snort_validation/generate_defender_configs.py`

For each defender profile:
1. Copy base `snort_et_c2.conf`
2. Enable/disable preprocessors as specified
3. Modify rule file to disable specified rules
4. Save to `snort_validation/defenders/<profile_name>/snort.conf`

### Step 3.3: Extend SnortBatchService to support defender selection
**File**: Modify `snort_validation/snort_batch_service.py`

```python
class SnortBatchService:
    def __init__(self, conf_path, defender_profile=None):
        if defender_profile:
            conf_path = f"snort_validation/defenders/{defender_profile}/snort.conf"
        self.conf_path = conf_path
        ...
    
    def query(self, packets, defender_profile=None):
        if defender_profile:
            temp_conf = f"snort_validation/defenders/{defender_profile}/snort.conf"
        else:
            temp_conf = self.conf_path
        # Use temp_conf for this query
        ...
```

### Step 3.4: Extend environment to sample defender per episode
**File**: Modify `ai_agent/hidden_defender_env.py`

```python
class HiddenDefenderEnv(gym.Env):
    def __init__(self, defender_profiles=['A', 'B', 'C', 'D', 'E']):
        self.defender_profiles = defender_profiles
        self.current_defender = None
        ...
    
    def reset(self):
        # Randomly pick a defender for this episode
        self.current_defender = np.random.choice(self.defender_profiles)
        obs = self._get_obs()
        return obs
    
    def step(self, action):
        # Query Snort with current defender
        verdict = self.service.query(packets, defender_profile=self.current_defender)
        ...
```

### Step 3.5: Train RL with heterogeneous defenders
**File**: Create `ai_agent/train_hidden_defender_ppo_heterogeneous.py`

```python
# Train for 200k steps (double, because harder)
env = HiddenDefenderEnv(defender_profiles=['A', 'B', 'C', 'D', 'E'])
agent = PPO(...)
agent.learn(total_timesteps=200000, log_interval=100)
```

**Expected behavior**:
- RL learns to probe (e.g., try split24, if fails → try http_header_pad)
- Policy generalizes across defenders
- Evasion success rate depends on defender randomness

### Step 3.6: Analyze learned policy
**File**: Create `snort_validation/analyze_heterogeneous_policy.py`

For each (flow, defender) pair:
```python
# Run trained policy
action_distribution = policy_histogram(flow, defender)
# Example: 
#   Defender A: split24 chosen 90%, pad chosen 10%
#   Defender B: split24 chosen 10%, pad chosen 80%
#   → Policy learned to adapt!
```

**Deliverable**: Report `reports/heterogeneous_defender_analysis.json`
- Action choice per (flow, defender) pair
- Success rate by defender
- Comparison: RL vs greedy per defender

---

## Comparison & Recommendations

| Direction | Effort | Complexity | Research Value | Expected RL Gain |
|-----------|--------|-----------|-----------------|-----------------|
| **1: Cost Penalty** | 1 day | Low | Medium (cost-aware learning) | Modest (policy diversity, not new mechanisms) |
| **2: Fix Snort** | 2–3 days | Medium | High (correct defense) | Significant (RL discovers new mechanisms) |
| **3: Heterogeneous** | 3–5 days | High | Very high (POMDP, generalization) | Excellent (RL needed for adaptation) |

---

## Implementation Order (Recommended)

1. **Start with Direction 1** (easiest): Implement cost penalty, verify RL learns cost-benefit trade-offs
   - Takes 1 day, quick win
   - Demonstrates RL can differentiate even when all mechanisms work

2. **Parallel Direction 2**: Debug Snort config, enable reassembly
   - Takes 2 days of investigation
   - Either fixes the config (good) or discovers we're already correct (interesting finding)

3. **If Direction 2 succeeds**: Train RL on fixed-defender setup
   - RL now has incentive to find new mechanisms
   - Strong paper narrative: "When defender is properly configured, RL discovers X"

4. **If time permits**: Direction 3 (heterogeneous defenders)
   - Most publishable: "RL generalizes across multiple defender configurations"
   - Classical POMDP problem, strong research angle

---

## Decision Matrix

**Choose Direction 1 if**: You want quick results and paper focus is on cost-aware evasion strategies
**Choose Direction 2 if**: You suspect Snort config is wrong and want to fix it properly
**Choose Direction 3 if**: You want strongest research contribution (RL + POMDP + generalization)

**Recommendation**: Do 1 + 2 in parallel, then decide on 3 based on Direction 2 results.
