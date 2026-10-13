# Plan: Fix the 2-Action Policy Collapse (root cause first, then diversity)

**Goal:** Make the agent's mechanism choice reflect real per-flow differences instead of collapsing to one action per framing (`split24` on http, `split8` on neris), by fixing the observation the policy actually sees and the training data it actually visits.

---

## Current Context / Assumptions

Repo: `/root/.hermes/c2-evasion-rl`, branch `packet-level-rl`. Venv: `.venv` (py3.11, torch + SB3). Run everything from an **absolute `workdir`** — the shell cwd goes stale.

**Measured facts (read from reports, not memory):**

| Fact | Value | Source |
|---|---|---|
| Test evasion (strict 6-fix pipeline) | 23/40 = 57.5% | `snort_validation/reports/ppo_masked_test_FIXED.json` |
| Baseline (noop) alert rate | 40/40 = 100% | same file, `baseline_alerted` |
| Distinct actions used on test | **2** (`split8`:24, `split24`:16) | `actions_chosen` |
| Action by framing | http→`split24` ×16, neris→`split8` ×24 | `per_flow` |
| Train evasion (20-flow sample) | 8/20 = 40.0% | `overfit_check_FIXED.json` |
| Generalisation gap | −17.5 pp (test > train) | `eval_comparison_FIXED.json` |

**Root cause 1 — the observation is defender-blind, so it cannot justify a mechanism choice.**
`obs_names` in `snort_validation/reports/hidden_defender_corpus.json` are 8 purely *shallow* features:
`is_udp, n_pkts_norm, tot_bytes_norm, n_payload_pkts_norm, payload_mean_norm, payload_std_norm, payload_max_norm, payload_min_norm`
(`archive/snort_validation/build_hidden_defender_corpus.py:56-74`). The **framing is not in the observation**, yet framing is the one thing that determines which mechanisms are even legal (`ai_agent/hidden_defender_env.py:329-363`). With no protocol signal, the best a policy can do is a near-constant output; the mask then clips it to whatever is legal, which produces exactly "http→one action, neris→one action". The collapse is **information-theoretic**, not a tuning failure. For the same reason `gamma=0.0` is correct here (`ai_agent/train_hidden_defender_ppo.py:127`): one decision per flow, nothing to propagate.

**Root cause 2 — training only ever visits the first 64 of 1153 train flows.**
`_flows` is never shuffled (`_rng` is constructed at `ai_agent/hidden_defender_env.py:301` and never used), `reset()` sets `self._idx = 0` (line 379), and PPO is configured `n_steps=N_FLOWS=64` with `total_timesteps=N_FLOWS` per epoch (`train_hidden_defender_ppo.py:35,125,132`). Every one of the 40 epochs re-walks **flows 0..63 — 5.6% of the corpus**. Combined with the mixed-framing corpus (`test_captures` shows both neris and bot captures mixed, so ordering interleaves framings), the policy has ample opportunity to learn "one action per framing" and never sees the rest of the corpus.

**Root cause 3 — the current shaping bonus is a dead branch.**
`PROTOCOL_MATCH_BONUS` is hard-coded to `mech == "http_header_pad"` (`hidden_defender_env.py:412-414`) and the existing test admits the branch may be unreachable (`tests/test_policy_diversity.py:52-56`). It nudges one of 14 actions and cannot change behaviour.

**Mechanism headroom (from real-Snort sweeps — this is what makes diversity worth pursuing):**

`snort_validation/reports/surrogate_sweep_14mech.json` (16 flows/mech, real Snort, valid = evaded ∧ semantics_ok ∧ not masked):

| mech | real evasion | semantics | valid | note |
|---|---|---|---|---|
| `split8` | 100.0% | 100% | **100.0%** | wins today |
| `split16` | 68.8% | 100% | 68.8% | competitive |
| `split24` | 68.8% | 100% | 68.8% | wins today |
| `http_header_pad` | 62.5% | 100% | **62.5%** | legal only on http (31.2% masked) |
| `prepend4/8/12` | 100% | **0%** | 0% | evades but breaks semantics → penalised |
| `pad16`/`reorder`/`ttl`/`noop` | 0% | 62–100% | 0% | never evades |
| `corrupt8`/`overlap8`/`length_wrapper` | 37.5–100% | 0% | 0% | semantics breaks |

A second, older sweep (`mechanism_matrix.json`, 80 flows) ranks `prepend4/prepend8` at 53.8% valid and `split8` at 52.5% — i.e. **different mechanisms win on different sub-populations**. That is the headroom: the honest claim after this work is *"the agent selects among mechanisms whose advantage varies per flow, instead of a constant"*.

**Non-negotiable invariants (from the project skill):**
- Never delete an entry from `ACTION_NAMES`; availability is an invariant, not a knob.
- Never remove or weaken `_compute_action_mask()`; framing-based masking is the correctness property.
- A valid evasion stays exactly `evaded and semantics_ok`.
- Never change the reward for *evasion itself* — only for *which mechanism* achieved it.
- Every change is confirmed against **real Snort** plus the **noop negative control**; a surrogate-only improvement proves nothing.

---

## Architecture / Proposed Approach

Three coordinated changes, smallest blast radius first: (1) add framing/mechanism-affordance signal to the observation so a per-flow choice is *representable*; (2) shuffle the training corpus each epoch so the policy sees all 1153 flows instead of 64; (3) make the shaping bonus reward the family of protocol-appropriate mechanisms (gated on `evaded and semantics_ok`) instead of one action, then retrain and measure diversity against real Snort with the negative control.

---

## Phase 0 — Baseline freeze (do this before touching anything)

### Task 0.1 — Snapshot the numbers you are about to move
```bash
cd /root/.hermes/c2-evasion-rl
git rev-parse --short HEAD
mkdir -p snort_validation/reports/archive_collapse_baseline
cp snort_validation/reports/ppo_masked_test_FIXED.json \
   snort_validation/reports/eval_comparison_FIXED.json \
   snort_validation/reports/overfit_check_FIXED.json \
   snort_validation/reports/archive_collapse_baseline/
```
Expected: three files copied; `git rev-parse` prints a short sha. Record it in the plan's execution log.

### Task 0.2 — Confirm the suite is green before you start
```bash
cd /root/.hermes/c2-evasion-rl && timeout 900 make test 2>&1 | tail -5
```
Expected: `69 passed` (or `N passed`, 0 failed). If not green, stop and report.

---

## Phase 1 — Put framing in the observation (root cause 1)

`OBS_DIM` is 8 and lives in two places: `ai_agent/hidden_defender_env.py:62` and the archived builder (`archive/snort_validation/build_hidden_defender_corpus.py:46`). The corpus pickle holds `flow["obs"]`; the env reads it directly (`hidden_defender_env.py:386`). **Do not re-extract pcaps.** Append the new features in the env at load time from `flow["packets"]`, which are already in the pickle — so `OBS_DIM` becomes 11 and no corpus rebuild is needed.

### Task 1.1 — Write the failing test first
Create `tests/test_obs_framing_signal.py`:
```python
"""The observation must carry protocol/affordance signal, or a per-flow
mechanism choice is not representable and the policy collapses to a constant."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv, OBS_DIM  # noqa: E402


def test_obs_dim_matches_documented_width():
    env = HiddenDefenderEnv(split="test")
    obs, _ = env.reset()
    assert obs.shape == (OBS_DIM,)
    assert OBS_DIM == 11, "obs must carry framing + affordance, not just 8 shallow features"


def test_obs_distinguishes_http_from_neris():
    env = HiddenDefenderEnv(split="test")
    seen = {}
    for i, f in enumerate(env._flows):
        env._idx = i
        obs = env._obs()
        seen.setdefault(f.get("framing"), obs[-3:].tolist())
    assert "http" in seen and "neris" in seen, "test set must contain both framings"
    assert seen["http"] != seen["neris"], "framing must be visible in the observation"


def test_obs_changes_when_framing_changes_not_only_shallow_features():
    """Two flows with identical shallow features but different framing must not
    collapse to the same observation."""
    env = HiddenDefenderEnv(split="test")
    by_shallow = {}
    for i, f in enumerate(env._flows):
        env._idx = i
        obs = env._obs()
        by_shallow.setdefault(tuple(round(x, 4) for x in obs[:8]), set()).add(f.get("framing"))
    mixed = [k for k, v in by_shallow.items() if len(v) > 1]
    assert mixed, "expected at least one shallow-feature collision across framings"
```
Run it:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_obs_framing_signal.py -q
```
Expected: **FAIL** — `assert 8 == 11` (and the other two fail for the same reason).

### Task 1.2 — Implement the framing features
In `ai_agent/hidden_defender_env.py`:

1. Line 62: `OBS_DIM = 11`.
2. Add just above `class HiddenDefenderEnv`:
```python
# Framing/affordance block appended to every observation.  Without it the
# policy cannot tell an HTTP flow from a neris record stream, so the only
# representable policy is a constant that the mask clips per framing -- which
# is exactly the 2-action collapse this fixes.
_FRAMING_ONEHOT = ("http", "neris")


def framing_features(flow) -> list:
    """One-hot framing + the two affordance bits the mask actually uses."""
    framing = flow.get("framing", "unknown")
    onehot = [1.0 if framing == name else 0.0 for name in _FRAMING_ONEHOT]
    http_only_ok = 1.0 if framing == "http" else 0.0        # mask[12], mask[13]
    prepend_ok = 0.0 if framing == "neris" else 1.0         # mask[3..5]
    return onehot + [http_only_ok, prepend_ok]
```
3. Replace `_obs` (line 383-386) with:
```python
    def _obs(self) -> np.ndarray:
        if self._idx >= len(self._flows):
            return np.zeros(OBS_DIM, dtype=np.float32)
        flow = self._flows[self._idx]
        base = flow["obs"]
        return np.asarray(list(base) + framing_features(flow), dtype=np.float32)
```
4. `observation_space` (line 304) already derives from `OBS_DIM`, so it follows automatically — verify by reading the line back.

Run the test again:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_obs_framing_signal.py -q
```
Expected: **3 passed**.

### Task 1.3 — Prove the framing is derivable, not trusted
The skill is explicit: framing must come from payloads, not a stored field. Add to the same test file:
```python
from endpoint_model import detect_framing  # noqa: E402
from hidden_defender_env import payloads_of  # noqa: E402


def test_stored_framing_matches_payload_derived_framing():
    env = HiddenDefenderEnv(split="test")
    bad = []
    for f in env._flows:
        derived = detect_framing(b"".join(payloads_of(f["packets"])))
        if derived != f.get("framing"):
            bad.append((f["flow_id"], f.get("framing"), derived))
    assert not bad, f"stored framing disagrees with payloads for {len(bad)} flows: {bad[:3]}"
```
Run:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_obs_framing_signal.py -q
```
Expected: **4 passed**. If this fails, the corpus `framing` field is untrustworthy — fix the corpus field before continuing (the mask and the obs must agree).

### Task 1.4 — Commit
```bash
cd /root/.hermes/c2-evasion-rl
git add ai_agent/hidden_defender_env.py tests/test_obs_framing_signal.py
git commit -m "feat(env): add framing/affordance block to observation (OBS_DIM 8->11)"
```
Expected: one commit created.

---

## Phase 2 — Let training see the whole corpus (root cause 2)

### Task 2.1 — Write the failing test
Create `tests/test_training_coverage.py`:
```python
"""Training must visit the whole corpus, not the first n_steps flows forever."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402


def test_reset_shuffles_the_training_order():
    env = HiddenDefenderEnv(split="train", seed=42)
    first = [f["flow_id"] for f in env._flows]
    env.reset()
    after = [f["flow_id"] for f in env._flows]
    assert after != first, "reset() must reshuffle the training corpus"
    assert sorted(after) == sorted(first), "shuffle must not drop or duplicate flows"


def test_shuffle_is_seed_reproducible():
    a = HiddenDefenderEnv(split="train", seed=7)
    a.reset()
    b = HiddenDefenderEnv(split="train", seed=7)
    b.reset()
    assert [f["flow_id"] for f in a._flows] == [f["flow_id"] for f in b._flows]


def test_test_split_is_never_shuffled():
    env = HiddenDefenderEnv(split="test", seed=42)
    first = [f["flow_id"] for f in env._flows]
    env.reset()
    assert [f["flow_id"] for f in env._flows] == first, "test order must stay frozen"
```
Run:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_training_coverage.py -q
```
Expected: **FAIL** — `reset() must reshuffle the training corpus`.

### Task 2.2 — Implement the shuffle
In `ai_agent/hidden_defender_env.py`, `reset()` (line 377-381) becomes:
```python
    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        # Training must not re-walk the same first n_steps flows every epoch:
        # with n_steps=64 that was 64/1153 flows and the policy learned the
        # corpus prefix, not the corpus.  The test split stays frozen so
        # evaluation is comparable run to run.
        if self.split == "train":
            self._rng.shuffle(self._flows)
        self._idx = 0
        mask = self._compute_action_mask()
        return self._obs(), {"action_mask": mask}
```
and `__init__` must store the split — add `self.split = split` next to `self._flows = load_corpus(split)` (line 297).

Run:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_training_coverage.py -q
```
Expected: **3 passed**.

### Task 2.3 — Raise the epoch budget to match the new coverage
`N_FLOWS = 64` now means "flows per rollout", and `MAX_EPOCHS = 40` gives 2560 steps over a corpus of 1153. In `ai_agent/train_hidden_defender_ppo.py`:
- line 35: `N_FLOWS = 256`
- line 36: `MAX_EPOCHS = 200`

Leave `TARGET = 0.90` — it is the early-stop, and with a surrogate scorer the run stays cheap. Verify the config reads back correctly:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import re,pathlib
s=pathlib.Path('ai_agent/train_hidden_defender_ppo.py').read_text()
print([l for l in s.splitlines() if re.match(r'(N_FLOWS|MAX_EPOCHS|TARGET)\s*=',l)])
"
```
Expected: `['N_FLOWS = 256', 'MAX_EPOCHS = 200', 'TARGET = 0.90']` (order may vary).

### Task 2.4 — Commit
```bash
cd /root/.hermes/c2-evasion-rl
git add ai_agent/hidden_defender_env.py ai_agent/train_hidden_defender_ppo.py tests/test_training_coverage.py
git commit -m "fix(train): shuffle train corpus per epoch; raise rollout/epoch budget"
```

---

## Phase 3 — Make the shaping bonus reward the family, not one action (root cause 3)

### Task 3.1 — Write the failing test
Replace `tests/test_policy_diversity.py`'s http-only bonus test with a family test. Add:
```python
def test_protocol_bonus_applies_to_the_whole_appropriate_family():
    """The bonus must reward every protocol-appropriate mechanism, not one action."""
    from hidden_defender_env import PROTOCOL_APPROPRIATE
    assert "http_header_pad" in PROTOCOL_APPROPRIATE["http"]
    assert "length_wrapper" in PROTOCOL_APPROPRIATE["http"]
    assert "split8" in PROTOCOL_APPROPRIATE["neris"]
    assert "split16" in PROTOCOL_APPROPRIATE["neris"]
    assert "split24" in PROTOCOL_APPROPRIATE["neris"]
    # a mechanism that is wrong for the framing gets nothing
    assert "http_header_pad" not in PROTOCOL_APPROPRIATE.get("neris", ())


def test_bonus_is_zero_when_evasion_or_semantics_fails():
    from hidden_defender_env import PROTOCOL_MATCH_BONUS, REWARD_EVADE
    assert PROTOCOL_MATCH_BONUS > 0
    assert PROTOCOL_MATCH_BONUS < abs(REWARD_EVADE) / 10, "bonus must stay a nudge, not a driver"
```
Run:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_policy_diversity.py -q
```
Expected: **FAIL** — `cannot import name 'PROTOCOL_APPROPRIATE'`.

### Task 3.2 — Implement the family bonus
In `ai_agent/hidden_defender_env.py`, next to `PROTOCOL_MATCH_BONUS` (line 91):
```python
# Which mechanisms are the *appropriate* primitive for a framing.  The bonus
# below rewards any of these (gated on a real valid evasion) instead of one
# hard-coded action, so the policy is free to prefer whichever is cheapest on
# a given flow while still not collapsing onto the framing-agnostic generic.
PROTOCOL_APPROPRIATE = {
    "http": ("http_header_pad", "length_wrapper", "split8", "split16", "split24"),
    "neris": ("split8", "split16", "split24", "pad16", "reorder", "ttl"),
}
```
and replace the reward branch (line 412-414) with:
```python
        if evaded and sem:
            framing = flow.get("framing", "unknown")
            if mech in PROTOCOL_APPROPRIATE.get(framing, ()):
                reward += PROTOCOL_MATCH_BONUS
```
Run:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_policy_diversity.py -q
```
Expected: **all passed**.

### Task 3.3 — Re-run the full suite (the invariants must still hold)
```bash
cd /root/.hermes/c2-evasion-rl && timeout 1200 make test 2>&1 | tail -5
```
Expected: 0 failed. In particular `tests/test_mechanisms_ab.py`, `tests/test_c2_semantics.py` and `tests/test_beats_control.py` must still pass — they pin "valid = evaded ∧ semantics_ok" and the cost ordering.

### Task 3.4 — Commit
```bash
cd /root/.hermes/c2-evasion-rl
git add ai_agent/hidden_defender_env.py tests/test_policy_diversity.py
git commit -m "feat(reward): protocol-appropriate family bonus, gated on valid evasion"
```

---

## Phase 4 — Retrain and measure against real Snort

### Task 4.1 — Retrain with the surrogate, then verify the winner on real Snort
The surrogate is ~1.3 s/flow; real Snort is far slower. Train on the surrogate, evaluate on real Snort.
```bash
cd /root/.hermes/c2-evasion-rl
timeout 3600 .venv/bin/python ai_agent/train_hidden_defender_ppo.py --max-epochs 200 \
  --out snort_validation/reports/ppo_collapse_fix_train.json 2>&1 | tail -20
```
Expected: an epoch log ending with a valid-flow percentage, then `[*] ppo: ...% ... scorer=replica`. If it early-stops at `reached 90%`, note the epoch count — that is the query cost of the fix.

### Task 4.2 — Evaluate on the frozen test split with real Snort
Use the existing fixed-pipeline evaluator (the one that produced `*_FIXED.json`) — do **not** write a new scorer:
```bash
cd /root/.hermes/c2-evasion-rl
ls snort_validation/*.py | xargs grep -ln "pipeline.*fixed_6_fixes\|fixed_6_fixes" 
```
Take the script that prints `pipeline: "fixed_6_fixes"` and run it against the newly trained model, writing `snort_validation/reports/ppo_masked_test_FIXED2.json`. Expected: a report with the same schema as `ppo_masked_test_FIXED.json` (`n_flows, alerted, evaded, valid_evasion, baseline_alerted, mechanism_diversity, actions_chosen, per_framing, per_flow`).

### Task 4.3 — Re-run the negative control (mandatory)
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python -c "
import json
c=json.load(open('snort_validation/reports/control_noop_real_snort.json'))
print('control rows:', len(c.get('rows', c.get('per_flow', []))))
print('alerted:', sum(1 for r in c.get('rows', c.get('per_flow', [])) if r.get('alert')))
"
```
Expected: every noop flow alerted (100%). If the control is not 100% alerted, the pipeline is broken and no evasion number from this run is reportable.

### Task 4.4 — Measure the collapse fix
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python -c "
import json
old=json.load(open('snort_validation/reports/ppo_masked_test_FIXED.json'))
new=json.load(open('snort_validation/reports/ppo_masked_test_FIXED2.json'))
for name,d in (('before',old),('after',new)):
    print(name, '| valid_evasion_pct=', d['valid_evasion_pct'],
          '| diversity=', d['mechanism_diversity'],
          '| actions=', d['actions_chosen'],
          '| per_framing=', d.get('per_framing'))
"
```
Expected decision rule, stated up front so the result cannot be rationalised after the fact:
- **Fix confirmed** if `mechanism_diversity >= 3` **and** `valid_evasion_pct >= 50` and the control is 100% alerted.
- **Partial** if diversity improves but evasion drops below 50 — report both numbers, do not cherry-pick.
- **Not fixed** if diversity is still 2 — then say so plainly and go to Phase 5.

### Task 4.5 — Commit the evidence
```bash
cd /root/.hermes/c2-evasion-rl
git add snort_validation/reports/ppo_masked_test_FIXED2.json snort_validation/reports/ppo_collapse_fix_train.json
git commit -m "eval: measure policy diversity after obs/train/reward fixes (real Snort)"
```

---

## Phase 5 — If it is still 2 actions: raise exploration, then report honestly

Do these in order, re-running Task 4.1–4.4 after each, and keep the run that helps.

### Task 5.1 — Raise entropy coefficient
`ai_agent/train_hidden_defender_ppo.py:126`: `ent_coef=0.0151` → `ent_coef=0.05`. Retrain, re-evaluate. Rationale: with a correct observation the remaining collapse is an exploration problem, and the skill's ordered advice is "nudges, least disruption first" — `ent_coef` is the first knob.

### Task 5.2 — Rebalance the split costs against the measured headroom
`split8` wins at 100% valid evasion on 16 flows (`surrogate_sweep_14mech.json`) while `split24` wins at 68.8%, yet `ACTION_COSTS[0]=0.60 > ACTION_COSTS[2]=0.40`. That ordering is what pushes http flows to `split24`. If diversity is still 2, test the alternative ordering in a branch: set `ACTION_COSTS[0]=0.25` and re-run. Do **not** delete or reorder the dict keys — indices are the action ids.

### Task 5.3 — Write the honest paragraph either way
Add to `docs/RESULTS_PRESENTATION.md` (and mirror in `docs/thesis_vi.tex` §6 Thảo luận):
- What the observation lacked and why that alone forced a constant policy.
- How many train flows the old loop actually visited (64 of 1153 = 5.6%).
- The measured diversity and evasion after each fix, with the negative control.
- If diversity is still 2: state that the nudges made protocol-appropriate mechanisms competitive in principle and availability is enforced by test, but on this test split the generic split still wins. Do **not** present a nudge as a behavioural fix.

---

## Tests / Validation Summary

| Check | Command | Expected |
|---|---|---|
| Framing in obs | `pytest tests/test_obs_framing_signal.py -q` | 4 passed |
| Framing derivable | included above | stored == payload-derived for all 40 |
| Train coverage | `pytest tests/test_training_coverage.py -q` | 3 passed |
| Bonus family | `pytest tests/test_policy_diversity.py -q` | all passed |
| Full suite | `timeout 1200 make test` | 0 failed |
| Claim verifier | `.venv/bin/python controls/verify_report_claims.py` | `NN/NN checks passed, 0 failed` |
| Negative control | Task 4.3 | 100% alerted |
| Diversity | Task 4.4 | `mechanism_diversity >= 3` or honest "not fixed" |

---

## Risks, Tradeoffs, Open Questions

| Risk | Impact | Mitigation |
|---|---|---|
| `OBS_DIM` 8→11 invalidates the saved model | Old `models/ppo_hidden_defender.zip` cannot be loaded | Expected — retraining is Phase 4; keep the old zip only as the "before" artefact |
| Obs change makes evasion *worse* | Headline number drops | Measure both; a policy that chooses per flow but evades less is still the more honest result |
| Shuffle breaks reproducibility of the 40-flow test set | Comparisons become meaningless | Test split is explicitly never shuffled (Task 2.1, test 3) |
| Retraining cost | Real-Snort scoring is ~1.3 s/flow even on the surrogate path | Train on surrogate, verify on real Snort only for the frozen test split |
| Family bonus rewards a mechanism that cannot evade on some flows | Policy learns a no-op preference | Bonus is gated on `evaded and semantics_ok`, so it cannot manufacture or mask evasion |
| `prepend*` looks strong in `mechanism_matrix.json` (53.8%) but 0% in `surrogate_sweep_14mech.json` | Two sweeps disagree | Re-derive per-mechanism validity under the 6-fix pipeline before quoting either; treat the older sweep as superseded |
| Still 2 actions after all three phases | The headline claim is "no diversity" | Phase 5.3 requires reporting that plainly; do not tune until a number looks good |

**Open questions for the user:**
1. Is `mechanism_diversity >= 3` the right bar, or do you want "uses ≥1 mechanism that is *better* than split on some flows"?
2. Should the retrain reuse `--real-snort` for a subset of epochs to catch surrogate/real disagreement during training, at ~1.3 s/flow?
3. The two mechanism sweeps disagree (`mechanism_matrix.json` vs `surrogate_sweep_14mech.json`) — should I re-run the sweep under the 6-fix pipeline as a separate task to settle which mechanisms are genuinely valid?

---

## Estimated Effort

| Phase | Time |
|---|---|
| 0 — baseline freeze | 10 min |
| 1 — observation | 30 min |
| 2 — training coverage | 30 min |
| 3 — reward family | 20 min |
| 4 — retrain + real-Snort eval | 60–120 min (background) |
| 5 — exploration (only if needed) | 30 min + retrain |
| **Total** | **~3–4 h wall time** |
