# Environment Architecture: Surrogate IDS vs Real Snort

---

## 1. Action Space

### Surrogate IDS (Original)
**14 discrete actions** (all applicable to all flows):
1. `noop` — không thay đổi
2. `split8` — fragment thành 2 packets (8 + rest bytes)
3. `split16` — fragment thành 2 packets (16 + rest bytes)
4. `split24` — fragment thành 2 packets (24 + rest bytes)
5. `prepend4` — thêm 4 byte junk ở đầu payload
6. `prepend8` — thêm 8 byte junk
7. `prepend12` — thêm 12 byte junk
8. `http_header_pad` — thêm HTTP header junk (vd: `X-Foo: bar\r\n`)
9. `length_wrapper` — wrap payload trong length-2 prefix
10. `reorder` — reorder TCP segments (out-of-order delivery)
11. `ttl` — set TTL thấp trên fragment đầu tiên (IDS skip expired packets)
12. `corrupt` — corrupt checksum trên fragment 1 (resend by TCP retransmission)
13. `overlap` — fragment với byte overlap (ambiguous reassembly)
14. `pad_payload` — append junk ở cuối payload (không ảnh hưởng command)

**Applicability**: 14/14 actions trên mọi flow (100%)

---

### Real Snort (Current)
**14 actions**, nhưng **protocol-filtered applicability**:

**Always applicable (4 mechanisms):**
1. `noop` — không thay đổi
2. `split8` — fragment 8 + rest
3. `split16` — fragment 16 + rest
4. `split24` — fragment 24 + rest

**HTTP-only (1 mechanism, 8/16 flows):**
5. `http_header_pad` — thêm HTTP header junk (requires HTTP framing)

**Length-prefixed protocol only (1 mechanism, 0/16 flows in corpus):**
6. `length_wrapper` — wrap trong length-2 prefix (requires "length2" framing)

**All protocol (8 mechanisms, 0/16 flows effective):**
7. `prepend4` — **0/16** (breaks protocol parser)
8. `prepend8` — **0/16** (breaks protocol parser)
9. `prepend12` — **0/16** (breaks protocol parser)
10. `reorder` — **0/16** (Snort rebuilds out-of-order before rule match)
11. `ttl` — **0/16** (Snort doesn't drop expired packets in pcap replay)
12. `corrupt` — **0/16** (broken checksum → packet invalid in pcap)
13. `overlap` — **0/16** (Snort's frag3 normalizes overlapping fragments)
14. `pad_payload` — **0/16** (endpoint protocol parser sees junk at command boundary)

**Effective applicability**:
- HTTP flows (8): 5/14 applicable (split8/16/24, http_header_pad, noop)
- Neris flows (8): 4/14 applicable (split8/16/24, noop)
- **Average**: 4.5/14 per flow (32%)

**Environment type: Whitebox** (rules visible, applicability known at step time)

---

## 2. Observation Space

### Surrogate IDS
**State vector per flow** (Python string matching):
- `packet_count`: int (how many packets in current flow)
- `total_bytes`: int (total payload bytes)
- `protocol`: string ("http" or other)
- `payload_sample`: first 256 bytes (for debugging)
- `current_rule_alerts`: int (how many ET C2 rules trigger on current packet)
- `is_evasion_active`: bool (whether any mechanism has been applied)

**Observation shape**: (~50 bytes per state, very lightweight)

**Update frequency**: After each action (deterministic, no actual IDS)

**Observation type: Whitebox** (agent sees exact rule count, protocol, payload)

---

### Real Snort
**State vector per flow** (via Snort batch service):
- `packet_count`: int
- `total_bytes`: int (original payload length)
- `protocol`: string (auto-detected via `endpoint_model.detect_framing()`)
  - Values: "http", "neris", "unknown"
- `applicable_mechanisms`: list of strings (filtered by protocol)
  - Example: ["noop", "split8", "split16", "split24", "http_header_pad"] for HTTP
  - Example: ["noop", "split8", "split16", "split24"] for Neris
- `last_verdict`: bool (did Snort alert on last query?)
- `evasion_count`: int (how many queries evaded so far)

**Observation shape**: (~100 bytes per state, slightly more than surrogate)

**Update frequency**: After each query to `SnortBatchService` (real binary call, ~10.6 sec per query)

**Observation type: Whitebox** (agent knows which mechanisms are applicable, sees real verdict)

---

## 3. Reward Signal

### Surrogate IDS
**Immediate reward per action**:
```
reward = +1 if action evades (Snort doesn't alert)
       = 0 if action fails (Snort alerts)
       = -0.1 if mechanism not applicable (penalty for invalid action)
```

**Episode reward**:
```
episode_reward = sum(rewards over all actions in episode)
               = (# evaded queries) / (total queries) — treated as success rate
```

**Verdict source**: Python replica of 20 ET C2 rules (simulated, fast but inaccurate)

---

### Real Snort
**Immediate reward per action**:
```
reward = +1 if action evades (real Snort doesn't alert)
       = 0 if action fails (real Snort alerts)
       = -0.1 if mechanism not applicable (prevented by mech_applicable filter)
```

**Episode reward**:
```
episode_reward = (# evaded queries) / (# applicable queries for this flow)
```

**Verdict source**: Real Snort binary with ET Open C2 ruleset (21,374 rules)

---

## 4. Environment Initialization & Dynamics

### Surrogate IDS
**Corpus**: 16 C2 flows (HTTP + Neris, but misclassified as all HTTP)
- Fixed, hand-picked C2 traffic samples
- Replayed deterministically

**Episode structure**:
1. Sample a flow uniformly at random
2. For 10 timesteps:
   - Agent selects action a
   - Action applied to flow packet(s)
   - RealRulesReplica checks rules → reward signal
   - State updated (packet count, rule alerts)
3. Episode ends after 10 timesteps or evasion achieved

**Determinism**: Fully deterministic (same flow → same alerts)

**Corpus size**: 16 flows, fixed

---

### Real Snort
**Corpus**: Same 16 C2 flows
- Framing auto-detected (50/50 HTTP/Neris)
- Replayed deterministically via PCAP

**Episode structure**:
1. Sample a flow uniformly at random
2. For up to 10 timesteps (or until evasion):
   - Agent selects action a (filtered by `mech_applicable()`)
   - Action applied to flow packet(s)
   - `SnortBatchService` writes PCAP → calls `snort -r` → verdict returned (~10.6 sec)
   - State updated (evasion_count, applicable_mechanisms)
3. Episode ends after 10 timesteps or evasion achieved

**Determinism**: Fully deterministic (same flow + action → same Snort verdict)

**Corpus size**: 16 flows, fixed

---

## 5. Policy Interface

### Surrogate IDS
**Agent input** (observation):
```python
obs = {
  'packet_count': 3,
  'total_bytes': 512,
  'protocol': 'http',
  'current_rule_alerts': 5,  # Exact count from Python rules
  'is_evasion_active': False
}
```

**Agent output** (action):
```python
action = env.action_space.sample()  # 0–13 (14 discrete actions)
```

**No constraint**: Agent can pick any action; no checking (environment allows invalid actions)

---

### Real Snort
**Agent input** (observation):
```python
obs = {
  'packet_count': 3,
  'total_bytes': 512,
  'protocol': 'neris',  # Auto-detected
  'applicable_mechanisms': ['noop', 'split8', 'split16', 'split24'],  # Only 4 valid
  'last_verdict': True,  # Did Snort alert on last query?
  'evasion_count': 0
}
```

**Agent output** (action):
```python
action = env.action_space.sample()  # 0–13, but only actions in applicable_mechanisms are valid
```

**Constraint**: Environment checks `mech_applicable(action, protocol)` before applying
- If action not applicable: reward = -0.1, no query to Snort (save time)
- If action applicable: query Snort, real verdict

---

## 6. Environment Transparency (Whitebox vs Blackbox)

### Surrogate IDS
**Whitebox** — agent observes:
- Exact number of triggered ET C2 rules (rule_alerts count)
- Protocol type (hardcoded as "http")
- Payload sample (first 256 bytes)
- No uncertainty: if rule_alerts = 0, evasion succeeded

**Implementation**: Python string matching on payload

**Query cost**: ~0.001 sec (negligible)

---

### Real Snort
**Whitebox hybrid**:
- Agent observes which mechanisms are applicable (whitelisted actions)
- Agent does NOT observe:
  - Individual rule triggers (only binary verdict: alert yes/no)
  - Which rules triggered
  - Internal Snort state (reassembly, normalization, etc.)
- Agent observes protocol type (auto-detected)

**Implementation**: Real Snort binary, binary verdict only

**Query cost**: ~10.6 sec per query (expensive, forces batch sampling)

---

## 7. Mechanism Feasibility

| Mechanism | Surrogate Result | Real Snort Result | Why Different? |
|-----------|-----------------|-------------------|-----------------|
| `split8/16/24` | 4/16 evade | 16/16 evade (100%) | Snort frag3 reassembly works correctly |
| `http_header_pad` | 4/8 evade | 8/8 evade (100%) on HTTP | HTTP parser accepts junk headers |
| `prepend4/8/12` | 4/16 evade | 0/16 evade | Endpoint parser fails on prepended junk |
| `reorder` | 4/16 evade | 0/16 evade | Snort rebuilds out-of-order before match |
| `ttl` | 4/16 evade | 0/16 evade | Snort doesn't expire packets in pcap |
| `corrupt` | 4/16 evade | 0/16 evade | Broken checksum → packet invalid |
| `overlap` | 4/16 evade | 0/16 evade | Snort's frag3 normalizes overlaps |
| `pad_payload` | 4/16 evade | 0/16 evade | Parser sees junk at command boundary |
| `length_wrapper` | 1/16 evade | 0/16 evade | No length-prefixed protocol in corpus |
| `noop` | 0/16 evade | 0/16 evade | No mechanism, so no evasion |

---

## 8. RL Agent Performance

### Surrogate IDS
**Baseline (greedy)**: 90.6% queries evaded (best mechanism per flow)
**RL (PPO, 14 actions)**: 90.6% queries evaded (same as greedy)
**Supervised tree**: 98.4% queries evaded

**Interpretation**: RL learned to pick split24/http_header_pad like greedy, but no advantage over baseline

---

### Real Snort
**Baseline (greedy)**: 90.6% queries evaded (best mechanism per flow = split24)
**RL (PPO, 14 actions)**: 90.6% queries evaded (collapses to split24)
**Supervised tree**: 98.4% queries evaded

**Interpretation**: RL still cannot outperform greedy; action space collapse due to only 4 mechanisms working

---

## 9. Summary Table

| Aspect | Surrogate IDS | Real Snort |
|--------|--------------|-----------|
| **Actions** | 14, all applicable | 14, but 4–5 effective |
| **Observations** | Whitebox (rule count visible) | Whitebox hybrid (verdict binary) |
| **Reward signal** | Fast (0.001 sec/query) | Slow (10.6 sec/query) |
| **Protocol detection** | Hardcoded (all "http") | Auto-detected (50/50 HTTP/Neris) |
| **Mechanism diversity** | 4–8 work per flow | 4 work (all 100%) |
| **RL performance** | 90.6% (same as greedy) | 90.6% (same as greedy) |
| **Verdict trustworthiness** | Low (replica rules) | High (real Snort) |
| **Environment complexity** | Simple (Python) | Complex (binary + PCAP I/O) |

---

## Key Insight: Why RL Cannot Learn

**Surrogate**: Diversity in mechanism effectiveness (4–8 each) → RL could learn which to pick
**Real Snort**: Uniformity in mechanism effectiveness (split8/16/24 all 100%) → no learning signal

RL thrives on diversity. When all mechanisms that work are equally good, greedy heuristic is optimal.

---

## Recommendation

To enable RL learning on real Snort, one of:
1. **Add harder baselines** (heterogeneous defender with adaptive rules)
2. **Expand test set** (larger corpus, more diverse flows)
3. **Constrain action space** (force RL to find non-obvious combinations)
4. **Accept that RL = greedy here** (and focus paper on protocol-aware design insights instead)
