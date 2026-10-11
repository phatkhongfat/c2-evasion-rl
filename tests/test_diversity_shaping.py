"""TDD: --diversity-coef frequency-penalty shaping (P4, 2026-10-11).

The penalty is a count-based exploration term applied ONLY to steps that are
already a valid evasion (invariant: shaping can never manufacture an evasion),
computed from the action-usage share within the current episode (= epoch).
Default coefficient 0.0 must leave the existing reward EXACTLY unchanged.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))


def test_frequency_penalty_math():
    from train_hidden_defender_ppo import frequency_penalty
    # first use of an action: count=0 -> no penalty
    assert frequency_penalty(counts={}, total=0, mech="split16", lam=0.5) == 0.0
    # after 3 valid evasions all split16, a 4th split16 is penalised by lam*1.0
    assert abs(frequency_penalty({"split16": 3}, 3, "split16", 0.5) - 0.5) < 1e-9
    # an unused action is never penalised
    assert frequency_penalty({"split16": 3}, 3, "split_slow", 0.5) == 0.0
    # lam=0 disables shaping entirely
    assert frequency_penalty({"split16": 9}, 9, "split16", 0.0) == 0.0


def test_penalty_is_bounded_below_evasion_reward():
    """Shaping must never outweigh a valid evasion (+10) or flip its sign."""
    from train_hidden_defender_ppo import frequency_penalty
    p = frequency_penalty({"split16": 999}, 999, "split16", 0.6)
    assert p <= 0.6 < 10.0


def test_train_cli_exposes_diversity_coef_defaulting_to_zero():
    main_src = (REPO / "ai_agent" / "train_hidden_defender_ppo.py").read_text()
    assert '"--diversity-coef"' in main_src
    # default must be 0.0 so existing reproductions are bit-identical
    assert 'default=0.0' in main_src.split('--diversity-coef')[1][:200]


def test_batch_env_applies_penalty_only_on_valid_evasion():
    """Integration: a stubbed inner env proves (a) valid-evasion reward is
    lowered by the share penalty, (b) alerted/broken steps are untouched."""
    from train_hidden_defender_ppo import BatchEnv
    import numpy as np

    env = BatchEnv.__new__(BatchEnv)          # bypass corpus + Snort
    env.diversity_coef = 0.5
    env._valid_counts = {}
    env._valid_total = 0
    env.n = 2
    env._i = 0

    calls = []

    class _Inner:
        action_space = None
        observation_space = None
        _flows = [{"flow_id": "f0"}, {"flow_id": "f1"}]

        def step(self, action):
            calls.append(action)
            info = dict(flow_id="f0", action="split16")
            if len(calls) == 1:               # first step: valid evasion
                info.update(evaded=True, semantics_ok=True, alert=False)
                return np.zeros(11, np.float32), 10.0, False, False, info
            info.update(evaded=False, semantics_ok=True, alert=True)
            return np.zeros(11, np.float32), -1.0, False, False, info

        def action_masks(self):
            return np.ones(15, dtype=np.int8)

    env.inner = _Inner()
    _o, r1, _t, _tr, _i = env.step(1)
    assert r1 == 10.0, "first use of an action carries no penalty"
    _o, r2, _t, _tr, _i = env.step(1)
    assert r2 == -1.0, "an alerted step must NOT be shaped"
    # third step: valid evasion again, now split16 share = 1/1 -> -0.5
    class _Inner2(_Inner):
        def step(self, action):
            calls.append(action)
            info = dict(flow_id="f1", action="split16",
                        evaded=True, semantics_ok=True, alert=False)
            return np.zeros(11, np.float32), 10.0, False, False, info
    env.inner = _Inner2()
    _o, r3, _t, _tr, _i = env.step(1)
    assert abs(r3 - 9.5) < 1e-9, f"share penalty missing: got {r3}"


def test_batch_env_reset_clears_penalty_counters():
    """The counters are per-episode (= per-epoch with n_steps=22): reset must
    zero them so epoch N+1 does not inherit epoch N's usage shares."""
    from train_hidden_defender_ppo import BatchEnv

    env = BatchEnv.__new__(BatchEnv)
    env.diversity_coef = 0.5
    env._valid_counts = {"split16": 5}
    env._valid_total = 5
    env._i = 3

    class _Inner:
        def reset(self, **kw):
            return None, {}
    env.inner = _Inner()
    env.reset()
    assert env._valid_counts == {}
    assert env._valid_total == 0
    assert env._i == 0
