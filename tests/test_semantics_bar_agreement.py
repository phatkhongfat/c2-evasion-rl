"""The training reward and the honest evaluation must use ONE semantics bar.

The training env (``hidden_defender_env``) and the evaluation pipeline
(``eval_pipeline``) both decide whether a mutation preserved the C2 command.
If they use different bars, the reward optimises for something the honest
metric scores as zero -- which is exactly how ``http_header_pad`` came to be
rewarded on HTTP while the honest eval scored every such flow as a semantics
break.

P15/D8 changed the reward gate from byte-only to ``bytes OR D7 OR D5`` (see
``docs/action_space_policy_p15.md``), so this test now pins TWO invariants:

  * the env's reward gate (``info['semantics_ok']`` / ``score()[1]``) equals
    ``c2_semantics.semantics_ok_reward`` -- the ONE D8 bar, shared with eval;
  * the env's strict byte verdict (``info['semantics_bytes']`` /
    ``score()[3]``) still equals the eval's ``bytes_equal_semantics``.

The env must therefore use the same client-only mutation as the evaluation.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from eval_pipeline import (  # noqa: E402
    bytes_equal_semantics,
    client_ip_of,
    mutate_client_only,
)
from c2_semantics import semantics_ok_reward  # noqa: E402
from hidden_defender_env import ACTION_NAMES, HiddenDefenderEnv  # noqa: E402


def test_env_and_eval_semantics_agree_on_every_mechanism():
    env = HiddenDefenderEnv(split="test", seed=42)
    gate_disagreements = {}
    byte_disagreements = {}
    n_pairs = 0
    for i, f in enumerate(env._flows):
        env._idx = i
        cip = client_ip_of(f["flow_id"])
        for mech in ACTION_NAMES:
            _evaded, env_sem, _alert, env_sem_bytes = env.score(f, mech)
            mut = mutate_client_only(f["packets"], mech, cip)
            eval_sem = bytes_equal_semantics(f["packets"], mut, cip)
            # D8 gate: the env reward gate must equal the shared D8 bar.
            eval_gate = semantics_ok_reward(f["packets"], mut, cip)
            # strict byte verdict: still the honest byte bar.
            eval_sem_bytes = eval_sem
            n_pairs += 1
            if bool(env_sem) != bool(eval_gate):
                gate_disagreements[mech] = gate_disagreements.get(mech, 0) + 1
            if bool(env_sem_bytes) != bool(eval_sem_bytes):
                byte_disagreements[mech] = byte_disagreements.get(mech, 0) + 1

    assert not gate_disagreements, (
        f"env D8 gate and eval semantics_ok_reward disagree on "
        f"{sum(gate_disagreements.values())}/{n_pairs} (flow, mechanism) pairs: "
        f"{gate_disagreements}"
    )
    assert not byte_disagreements, (
        f"env byte verdict and eval bytes_equal_semantics disagree on "
        f"{sum(byte_disagreements.values())}/{n_pairs} (flow, mechanism) pairs: "
        f"{byte_disagreements}"
    )
