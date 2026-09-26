"""Determinism regression tests for ``ai_agent/eval_cross_capture.py``.

The eval script used to print a different baseline evasion on every run
(observed across runs: 0.02, 0.04, 0.06, 0.10) because two RNG sources were
never seeded:

  1. ``env.reset()`` was called with no seed, so the flow drawn per episode
     varied from process to process.
  2. ``env.action_space.sample()`` draws from gymnasium's ``Space.np_random``,
     which lazily self-seeds from OS entropy on first use.  ``np.random.seed()``
     cannot reach it.  This is the *baseline* arm -- the number the agent is
     compared against.

All three tests below fail on the pre-fix script and pass after it.

Note: ``test_three_consecutive_runs_produce_identical_report_bytes`` runs the
real script, so it rewrites ``snort_validation/reports/cross_capture_eval.json``
as a side effect.  That is the artifact under test; each run must produce the
same bytes.
"""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = Path(
    os.environ.get(
        "EVAL_CROSS_CAPTURE_SCRIPT", REPO / "ai_agent" / "eval_cross_capture.py"
    )
)
REPORT = REPO / "snort_validation" / "reports" / "cross_capture_eval.json"

sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

N_RUNS = 3
TIMEOUT_S = 900


def _load_module():
    """Import the eval script as a module (its main() is __main__-guarded)."""
    spec = importlib.util.spec_from_file_location("eval_cross_capture", SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {SCRIPT}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_script():
    """Run the eval script in a fresh process; return (report bytes, stdout)."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )
    assert proc.returncode == 0, (
        f"eval script exited {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    assert REPORT.exists(), "eval script did not write the report"
    return REPORT.read_bytes(), proc.stdout


def _dummy_pool(n):
    """Homogeneous pool: only the action stream can vary between runs."""
    return [
        {
            "flow_tag": i,
            "tot_pkts": 4,
            "tot_bytes": 2000,
            "src_bytes": 500,
            "dur": 1.0,
            "proto": "tcp",
            "state": "CON",
        }
        for i in range(n)
    ]


def test_three_consecutive_runs_produce_identical_report_bytes():
    """Cross-process: OS entropy differs per process, so this catches the bug."""
    runs = [_run_script() for _ in range(N_RUNS)]
    first_bytes = runs[0][0]
    for i, (raw, stdout) in enumerate(runs[1:], start=2):
        assert raw == first_bytes, (
            f"run {i} report differs from run 1 -- eval is non-deterministic.\n"
            f"run 1: {json.loads(first_bytes)}\n"
            f"run {i}: {json.loads(raw)}\n"
            f"--- run {i} stdout ---\n{stdout}"
        )


def test_eval_policy_is_reproducible_in_process():
    """The baseline arm's RNG must not self-seed from OS entropy."""
    mod = _load_module()
    pool = _dummy_pool(8)
    runs = [mod.eval_policy(pool, policy=None, n_episodes=8) for _ in range(3)]
    assert len(set(runs)) == 1, f"baseline eval is non-deterministic: {runs}"


def test_eval_policy_walks_the_pool_one_to_one(monkeypatch):
    """Episode `ep` must evaluate pool[ep]; no flow repeated or skipped."""
    mod = _load_module()
    seen = []

    class RecordingEnv(mod.EnhancedPacketLevelEnv):
        def reset(self, seed=None, options=None):
            seen.append(self.malicious_pool[0]["flow_tag"])
            return super().reset(seed=seed, options=options)

    monkeypatch.setattr(mod, "EnhancedPacketLevelEnv", RecordingEnv)
    pool = _dummy_pool(6)
    mod.eval_policy(pool, policy=None, n_episodes=6)
    assert seen == list(range(6)), f"pool was not walked 1:1: {seen}"
