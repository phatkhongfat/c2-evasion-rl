# Why Evasion Rate Is Hard to Raise

Investigation into barriers preventing higher evasion rates on tcp_pkt>=10 subset.

## Current Status

- **Best model**: tcp10-trained 50K steps
- **Evasion**: 30.27% (5-seed measurement) / 27.7% (3-seed in experiments)
- **Gap vs random**: +11.33 pp
- **Detection rate**: ~70%

## Hyperparameter Tuning Results (3 experiments)

| Variant | Steps | Evasion | Delta vs baseline |
|---------|-------|---------|-------------------|
| **Baseline** | 50K | 27.7% | — |
| More training | 100K | 27.7% | **+0.0 pp** |
| Higher entropy (ent_coef=0.05) | 50K | 27.7% | **+0.0 pp** |
| Larger batch (n_steps=512, batch=128) | 50K | 26.3% | **−1.3 pp** |

**Verdict:** No hyperparameter combination tested improved over the baseline. More training steps, more exploration, and larger batches all failed to move the needle.

## Root Cause Analysis

### 1. **The action space is severely limited**

From action distribution analysis over 100 episodes (687 total actions):

```
padding_bytes:  mean=-1.000 std=0.000 min=-1.000 max=-1.000
                ⚠️ COLLAPSED — policy pegged at -1.0 (min padding)
```

**The policy uses only ONE of the four action dimensions.** `padding_bytes` is locked at -1.0 (minimum padding) on every single step — it has learned that min padding is always optimal and never explores alternatives.

The other three dimensions show variation:
- `ttl_delta`: mean=-0.632, std=0.111
- `frag_flag`: mean=0.185, std=0.069  
- `tcp_overlap`: mean=0.529, std=0.190

**But these three don't reach the reward function** — only `tot_bytes` and `src_bytes` (which `padding` affects) are visible to `replica_snort_verdict()`. TTL, fragmentation, and overlap are recorded but never influence the verdict.

### 2. **The reward function ceiling**

The 6-rule Snort replica has fixed thresholds:
- `sid:3000001`: ≥3 packets with dsize>800 in 120s
- `sid:3000002`: ≥3 packets with dsize>1200 in 120s
- `sid:3000003`: ≥5 UDP packets with dsize≤65 in 30s
- `sid:3000004`: ≥8 TCP packets with dsize≤65 in 60s
- `sid:3000006`: single packet with dsize>1400

For flows in `tcp_pkt>=10` that trip these thresholds, **reducing padding alone often can't evade** — the packet count and byte volume are already over the line. The agent learned to minimize padding (27.7% evasion), but 70% of flows remain detectable because:
- They have too many packets (≥8 small or ≥3 large)
- Padding reduction can't drop them below threshold without eliminating packets entirely (which the env doesn't allow)

### 3. **Episode length is short**

From the 50K training log: `ep_len_mean = 6.5 steps`. The agent gets 6-7 actions per episode on average before termination. With only one effective action dimension (padding) and a median of ~10-20 packets per flow, there's limited room to compound mutations.

## What Would Actually Help

Based on this analysis, **none of these would work:**
- ❌ More training steps (tested: 0.0 pp improvement)
- ❌ Different hyperparameters (tested: no improvement or degradation)
- ❌ Reward shaping (padding is already learned optimally)

**What might work:**

1. **Fix the action→reward path** — Make TTL, fragmentation, and TCP overlap actually influence the Snort verdict, so the agent has 4 dimensions to learn instead of 1.

2. **Expand the action space** — Allow the agent to:
   - Drop packets (reduce count below thresholds)
   - Split large packets into smaller ones
   - Delay packets to spread bursts across threshold windows
   
3. **Adversarial rule training** — The current rules are static. Train against a defender that adapts its thresholds based on what the agent learns.

4. **Ensemble policies** — Train separate specialists for different flow types (small-packet flows vs large-packet flows) and route at inference time.

## Conclusion

The current approach has reached its ceiling at ~30% evasion because:
- The policy can only control one dimension (padding)
- That dimension is already optimized (always min padding)
- 70% of flows trip thresholds that padding alone can't fix

**More training will not help.** The constraint is the environment's limited action→reward coupling, not the optimization budget. The next step is fixing the env (make TTL/frag/overlap matter) or expanding the action space (packet dropping, splitting, timing).
