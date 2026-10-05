"""The observation must carry protocol/affordance signal, or a per-flow
mechanism choice is not representable and the policy collapses to a constant."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from endpoint_model import detect_framing  # noqa: E402
from hidden_defender_env import (  # noqa: E402
    OBS_DIM,
    HiddenDefenderEnv,
    framing_features,
    payloads_of,
)


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
    collapse to the same observation.

    The plan's version scanned the shipped test split for a cross-framing
    collision of the 8 shallow features.  That collision does not exist in this
    corpus (measured: 0 such groups in both splits), so the scan would assert an
    empty premise.  The same property is exercised deterministically with a
    synthetic pair that shares a shallow block and differs only in framing.
    """
    env = HiddenDefenderEnv(split="test")
    shallow = list(env._flows[0]["obs"])
    http_flow = {"framing": "http", "obs": shallow}
    neris_flow = {"framing": "neris", "obs": shallow}
    assert framing_features(http_flow) != framing_features(neris_flow)

    env._flows = [http_flow, neris_flow]
    env._idx = 0
    obs_http = env._obs()
    env._idx = 1
    obs_neris = env._obs()
    assert obs_http[:8].tolist() == obs_neris[:8].tolist(), "shallow block must match"
    assert obs_http.tolist() != obs_neris.tolist(), \
        "framing must separate identical shallow features"


def test_stored_framing_matches_payload_derived_framing():
    env = HiddenDefenderEnv(split="test")
    bad = []
    for f in env._flows:
        derived = detect_framing(b"".join(payloads_of(f["packets"])))
        if derived != f.get("framing"):
            bad.append((f["flow_id"], f.get("framing"), derived))
    assert not bad, f"stored framing disagrees with payloads for {len(bad)} flows: {bad[:3]}"
