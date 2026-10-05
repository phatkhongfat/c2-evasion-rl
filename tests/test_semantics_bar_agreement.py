"""The training reward and the honest evaluation must use ONE semantics bar.

The training env (``hidden_defender_env``) and the evaluation pipeline
(``eval_pipeline``) both decide whether a mutation preserved the C2 command.
If they use different bars, the reward optimises for something the honest
metric scores as zero -- which is exactly how ``http_header_pad`` came to be
rewarded on HTTP while the honest eval scored every such flow as a semantics
break.

This test pins the invariant: for every test flow and every one of the 14
mechanisms, the env's semantics verdict and the eval's byte-equality verdict
must agree.  The env must therefore use the same client-only mutation and the
same reassembled-client-stream byte rule as the evaluation.
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
from hidden_defender_env import ACTION_NAMES, HiddenDefenderEnv  # noqa: E402


def test_env_and_eval_semantics_agree_on_every_mechanism():
    env = HiddenDefenderEnv(split="test", seed=42)
    disagreements = {}
    n_pairs = 0
    for i, f in enumerate(env._flows):
        env._idx = i
        cip = client_ip_of(f["flow_id"])
        for mech in ACTION_NAMES:
            _evaded, env_sem, _alert = env.score(f, mech)
            eval_sem = bytes_equal_semantics(
                f["packets"],
                mutate_client_only(f["packets"], mech, cip),
                cip,
            )
            n_pairs += 1
            if bool(env_sem) != bool(eval_sem):
                disagreements[mech] = disagreements.get(mech, 0) + 1

    assert not disagreements, (
        f"env semantics and eval byte-equality disagree on "
        f"{sum(disagreements.values())}/{n_pairs} (flow, mechanism) pairs: "
        f"{disagreements}"
    )
