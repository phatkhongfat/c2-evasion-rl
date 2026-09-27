# Fix unseeded randomness in `ai_agent/eval_cross_capture.py`

## Goal

Make `ai_agent/eval_cross_capture.py` produce bit-identical baseline and agent
evasion numbers on every run, so the `snort_validation/reports/cross_capture_eval.json`
artifact is reproducible and its committed numbers are trustworthy.

## Current context / assumptions

- Repo root: `/root/.hermes/c2-evasion-rl`. Python interpreter is
  `/root/.hermes/c2-evasion-rl/.venv/bin/python` (gymnasium 1.3.0, stable-baselines3,
  pandas, numpy). Run every command from the repo root.
- The three files under review:
  - `ai_agent/eval_cross_capture.py` — **the only file that needs changing.**
  - `scripts/measure_action_impact.py` — verified deterministic across two runs
    (byte-identical table). Leave alone.
  - `scripts/trace_action_to_reward.py` — verified correct: its "BUG CONFIRMED"
    printout is backed by `packet_modifier.to_flow_features()` returning only
    `['dur','proto','src_bytes','state','tot_bytes','tot_pkts']`. Leave alone.
- `EnhancedPacketLevelEnv.__init__` accepts `seed=None` and calls `self.seed(seed)`,
  which does `np.random.seed(seed)` — this seeds the **global** numpy legacy RNG only.
- `EnhancedPacketLevelEnv.reset(seed=None, ...)` picks a flow with
  `np.random.randint(0, len(self.malicious_pool))` (global RNG) and **never
  registers a `gymnasium.utils.seeding` RNG on the env or its spaces**.
- `gymnasium.spaces.Space.sample()` uses `Space._np_random`, which is lazily created
  from `seeding.np_random()` with `seed=None` → seeded from OS entropy. It is
  completely independent of `np.random.seed(...)`. Verified empirically:
  `np.random.seed(456); spaces.Box(...).sample()` returns different values on repeat.
- Observed symptom (this session, 3 runs of the script): baseline evasion printed
  `2.0%`, `4.0%`, `10.0%`; agent evasion was a stable `80.0%`. The committed report
  `snort_validation/reports/cross_capture_eval.json` says `baseline_evasion: 0.06,
  delta_pp: 74.0`, which matches no recent run.
- Note on scope: a *separate*, unfixed bug was also observed (MCFP records lack the
  `dur` / `src_bytes` / `state` keys the env's `packet_plan()` reads, so flows fall
  back to `_clamp_features` defaults). That is out of scope here — see Open Questions.
  Do not fix it in this change; it would alter the headline numbers.

## Architecture / proposed approach

Seed **all three** sources of randomness explicitly, in the one place that creates
the env. The clean fix is to stop relying on `np.random.seed` and instead give the
env a deterministic per-episode seed and give the action space a deterministic
generator:

1. Call `env.reset(seed=<deterministic value>)` per episode instead of bare
   `env.reset()`, so flow selection is reproducible.
2. Call `env.action_space.seed(<deterministic value>)` once, so
   `env.action_space.sample()` draws from a seeded `gymnasium` RNG rather than
   OS entropy.

Both seeds derive from the existing `seed=456` constant, so no new CLI args and no
behaviour change other than determinism. Keep it minimal: two lines in
`eval_policy()`, plus a docstring note.

## Step-by-step tasks

### Task 1 — Write the failing determinism test

Create `tests/test_eval_cross_capture_determinism.py`. There is no `tests/`
directory in this repo yet; create it.

```python
# tests/test_eval_cross_capture_determinism.py
"""eval_policy() must be bit-identical across repeated calls in one process."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

import numpy as np
import pandas as pd
import pytest

from enhanced_packet_level_env import EnhancedPacketLevelEnv


def _eval_policy(pool, policy=None, n_episodes=10, seed=456):
    env = EnhancedPacketLevelEnv(pool, max_packets_per_flow=50, seed=seed)
    evaded = 0
    for _ep in range(n_episodes):
        obs, info = env.reset()          # <-- unseeded: the bug under test
        done = False
        while not done:
            action = env.action_space.sample()   # <-- unseeded: the bug under test
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
        if not info.get("detected", False):
            evaded += 1
    return evaded / n_episodes


@pytest.fixture(scope="module")
def pool():
    df = pd.read_parquet(REPO / "data" / "mcfp_snort_labeled.parquet")
    df["capture"] = df["capture"].astype(str)
    caps = df["capture"].unique()
    sub = df[df["capture"] == caps[1]]
    np.random.seed(456)
    idx = np.random.choice(len(sub), min(10, len(sub)), replace=False)
    return sub.iloc[idx].to_dict("records")


def test_baseline_eval_is_reproducible(pool):
    runs = [_eval_policy(pool, policy=None, n_episodes=10) for _ in range(3)]
    assert len(set(runs)) == 1, f"baseline eval is non-deterministic: {runs}"


def test_baseline_action_stream_is_reproducible(pool):
    """Sample the same action stream twice from two envs built the same way."""
    streams = []
    for _ in range(2):
        env = EnhancedPacketLevelEnv(pool, max_packets_per_flow=50, seed=456)
        streams.append([tuple(env.action_space.sample()) for _ in range(5)])
    assert streams[0] == streams[1], "action_space.sample() stream differs between envs"
```

Run it and watch it fail:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_eval_cross_capture_determinism.py -v
```

Expected: `test_baseline_action_stream_is_reproducible` FAILS, and
`test_baseline_eval_is_reproducible` usually FAILS too. If the second one
passes by luck, it is not a reliable test — rely on the action-stream test plus
the cross-process check in Task 3.

Commit:

```bash
git add tests/test_eval_cross_capture_determinism.py
git commit -m "test: capture the unseeded-RNG bug in eval_cross_capture eval_policy"
```

### Task 2 — Seed the env and the action space in `eval_policy()`

Edit `ai_agent/eval_cross_capture.py`, replacing the body of `eval_policy`
(lines 57-77) with:

```python
def eval_policy(pool, policy=None, n_episodes=None, seed=456):
    if n_episodes is None:
        n_episodes = len(pool)
    env = EnhancedPacketLevelEnv(pool, max_packets_per_flow=50, seed=seed)
    # gymnasium seeds Space._np_random from OS entropy on first .sample() unless
    # the space is seeded explicitly; np.random.seed() (done by the env's
    # constructor) does not reach it.  Seed it so the baseline is reproducible.
    env.action_space.seed(seed)

    evaded = 0
    for ep in range(n_episodes):
        # Per-episode seed: re-seeding every reset makes flow selection
        # independent of how many RNG draws previous episodes consumed.
        obs, info = env.reset(seed=seed + ep)
        done = False
        while not done:
            if policy is None:
                action = env.action_space.sample()
            else:
                action, _ = policy.predict(obs, deterministic=True)
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated

        if not info.get("detected", False):
            evaded += 1

    return evaded / n_episodes
```

Two notes for the implementer:

- `EnhancedPacketLevelEnv.reset()` ignores a `seed` argument **only** in the sense
  that it does not use `gymnasium`'s env-level RNG — it calls `self.seed(seed)`
  when `seed is not None`, which is `np.random.seed(seed)`, and then uses
  `np.random.randint`. Passing `seed=seed + ep` therefore works and re-seeds the
  flow draw each episode. Verified: the current code already gets deterministic
  `info["flow_id"]` sequences per arm, so this only makes it explicit.
- The two `eval_policy(...)` call sites at lines 80-81 stay unchanged; the new
  `seed` parameter defaults to 456.

Run the test again:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_eval_cross_capture_determinism.py -v
```

Expected: **2 passed**.

Commit:

```bash
git add ai_agent/eval_cross_capture.py
git commit -m "fix: seed action space and per-episode flow draw in eval_policy"
```

### Task 3 — Verify end-to-end across separate processes

Cross-process is the real test: OS entropy differs per process, so two runs
printed different baseline numbers before the fix.

```bash
cd /root/.hermes/c2-evasion-rl && for i in 1 2 3; do .venv/bin/python ai_agent/eval_cross_capture.py 2>&1 | grep -E "Baseline|Enhanced agent|Delta"; echo "---"; done
```

Expected after the fix: all three runs print the **same** `Baseline: 2.0%`
(or whatever the single true value is), the same `Enhanced agent: 80.0%`, and the
same `Delta: +78.0pp`. Before the fix this block printed 2.0/10.0/10.0.

Then confirm the report file on disk matches, and note the new true value:

```bash
cd /root/.hermes/c2-evasion-rl && cat snort_validation/reports/cross_capture_eval.json
```

The committed file currently claims `baseline_evasion: 0.06, delta_pp: 74.0`,
which was never reproducible. Commit the regenerated report with an honest message
that says the old number was wrong:

```bash
git add snort_validation/reports/cross_capture_eval.json
git commit -m "fix(report): regenerate cross_capture_eval.json under seeded RNG

The previously committed baseline_evasion 0.06 / delta_pp 74.0 was not
reproducible; repeated runs produced baseline 0.02-0.10 because the random
baseline drew actions from an unseeded gymnasium space RNG."
```

### Task 4 — Confirm the other two scripts are still untouched and deterministic

No code change. This is a regression check only.

```bash
cd /root/.hermes/c2-evasion-rl && git diff --stat HEAD~3 -- scripts/measure_action_impact.py scripts/trace_action_to_reward.py
```

Expected: empty output (neither file was modified by Tasks 1-3).

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python scripts/trace_action_to_reward.py 2>&1 | tail -12
```

Expected: ends with the `ENHANCED REPLICA - TTL RULE REACHABILITY` block showing
`P1/P2/P5 => UNREACHABLE` and `empirical worst-case TTL action -> enhanced verdict: evaded`.

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python scripts/measure_action_impact.py 2>&1 | tail -10
```

Expected: the `EnhancedPacketLevelEnv` table, with `overlap_offset` showing the only
non-zero spread (`~10.08`); `ttl_delta` and `padding_bytes` at `0.00`. Runs for a
few minutes and loads the full CTU-13 pool (~2.3 GB) — give it a generous timeout.

## Tests / validation

- Unit: `tests/test_eval_cross_capture_determinism.py` — 2 tests, both must pass
  after Task 2 and at least the action-stream one must fail before it.
- Cross-process: the Task 3 shell loop must print three identical result blocks.
  This is the check that actually catches the bug class; the in-process unit test
  alone can pass by chance because both arms happen to draw the same flows.
- Artefact check: `snort_validation/reports/cross_capture_eval.json` after
  regeneration must equal what the last run printed, and `git status --porcelain`
  must be clean of unexpected modifications.
- Full suite: `.venv/bin/python -m pytest tests/ -v` → 2 passed.

## Risks, tradeoffs, and open questions

- **The headline number will change.** The committed `delta_pp: 74.0` came from a
  non-reproducible run. The honest delta is whatever the seeded run prints. That is
  the point of the fix, but whoever owns this project should be told before the
  report diff lands, since 74.0pp may be quoted elsewhere.
- **Fixing determinism does not make the baseline a fair baseline.** The baseline
  samples uniformly from the full `[-1, 1]` action box, so it routinely trips the
  enhanced replica's fragmentation/overlap rules. A lower baseline is expected and
  is not evidence the agent is good. Worth a follow-up, out of scope here.
- **Seeding every episode (`seed + ep`) slightly changes which flows are evaluated**
  relative to the old behaviour, because the flow draw is re-seeded per episode
  rather than continuing one stream. This is intentional and makes arms independent
  of episode count, but it means baseline and agent must both use the new call to
  stay paired. They do — both go through the same `eval_policy`.
- **Out of scope, but should be filed: MCFP/env schema mismatch.** The MCFP parquet
  has `flow_duration` / `fwd_bytes`, but `packet_plan()` reads `dur` / `src_bytes` /
  `state`, so every eval flow falls back to defaults (`src_bytes=500`, `dur=1.0`).
  Measured this session: all 50 sampled rows mismatch, and mapping the columns
  correctly moves agent evasion from 0.80 to 0.84. This is a real correctness
  problem in the measurement, independent of the seeding bug. Fixing it changes the
  numbers again, so it belongs in its own commit.
