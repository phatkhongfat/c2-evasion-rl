"""
Tests for C2EvasionEnv.

Run:
    pytest -q test_c2_evasion_env.py

The tests are self-contained: they create a tiny surrogate model and
LabelEncoders in a temporary directory, so they do not require the
real CTU-13 artifacts.

Expected environment contract:
    observation = [dur, tot_pkts, tot_bytes, src_bytes, proto, state]
    action      = [jitter, padding, header_variant]
"""

from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import LabelEncoder

from c2_evasion_env import C2EvasionEnv


@pytest.fixture()
def artifacts(tmp_path: Path):
    """Create minimal compatible model/encoder artifacts."""
    # Six features, matching train_surrogate.ipynb.
    x = np.array(
        [
            [1.0, 10.0, 100.0, 50.0, 0.0, 0.0],
            [2.0, 20.0, 200.0, 80.0, 1.0, 1.0],
        ],
        dtype=np.float32,
    )
    y = np.array([0, 1])

    model = DummyClassifier(strategy="constant", constant=1)
    model.fit(x, y)

    proto_encoder = LabelEncoder()
    proto_encoder.fit(["tcp", "udp"])

    state_encoder = LabelEncoder()
    state_encoder.fit(["CON", "INT"])

    model_path = tmp_path / "surrogate.pkl"
    proto_path = tmp_path / "proto_encoder.pkl"
    state_path = tmp_path / "state_encoder.pkl"

    joblib.dump(model, model_path)
    joblib.dump(proto_encoder, proto_path)
    joblib.dump(state_encoder, state_path)

    return {
        "model_path": model_path,
        "proto_path": proto_path,
        "state_path": state_path,
    }


@pytest.fixture()
def malicious_pool():
    """Small pool containing dict samples compatible with the environment."""
    return [
        {
            "dur": 10.0,
            "tot_pkts": 42.0,
            "tot_bytes": 500.0,
            "src_bytes": 250.0,
            "proto": "tcp",
            "state": "CON",
            "label": "flow=From-Botnet-Test",
        },
        {
            "dur": 20.0,
            "tot_pkts": 84.0,
            "tot_bytes": 800.0,
            "src_bytes": 400.0,
            "proto": "udp",
            "state": "INT",
            "label": "flow=From-Botnet-Test-2",
        },
    ]


@pytest.fixture()
def env(artifacts, malicious_pool):
    return C2EvasionEnv(
        malicious_data_pool=malicious_pool,
        model_path=str(artifacts["model_path"]),
        proto_encoder_path=str(artifacts["proto_path"]),
        state_encoder_path=str(artifacts["state_path"]),
        max_steps=3,
        debug=False,
    )


def test_spaces_are_defined_correctly(env):
    assert env.action_space.shape == (3,)
    assert env.observation_space.shape == (6,)

    np.testing.assert_array_equal(
        env.action_space.low,
        np.array([0.0, 0.0, 0.0], dtype=np.float32),
    )
    np.testing.assert_array_equal(
        env.action_space.high,
        np.array([10.0, 1000.0, 3.0], dtype=np.float32),
    )


def test_reset_is_reproducible(env):
    obs1, info1 = env.reset(seed=123)
    obs2, info2 = env.reset(seed=123)

    np.testing.assert_array_equal(obs1, obs2)
    assert info1["sample_idx"] == info2["sample_idx"]
    assert info1["step"] == 0
    assert info2["step"] == 0


def test_reset_returns_valid_observation(env):
    obs, info = env.reset(seed=0)

    assert isinstance(obs, np.ndarray)
    assert obs.dtype == np.float32
    assert obs.shape == (6,)
    assert env.observation_space.contains(obs)

    assert isinstance(info, dict)
    assert "sample_idx" in info
    assert info["step"] == 0


def test_step_applies_jitter_and_padding(env):
    env.reset(seed=0)

    before = env.current_sample.copy()

    action = np.array([2.5, 100.0, 1.4], dtype=np.float32)
    obs, reward, terminated, truncated, info = env.step(action)

    assert env.step_count == 1

    assert env.current_sample["dur"] == pytest.approx(before["dur"] + 2.5)
    assert env.current_sample["tot_bytes"] == pytest.approx(
        before["tot_bytes"] + 100.0
    )
    assert env.current_sample["src_bytes"] == pytest.approx(
        before["src_bytes"] + 100.0
    )

    # 1.4 is rounded to header variant 1.
    assert env.current_sample["HeaderVariant"] == 1
    assert info["header_variant"] == 1

    assert obs.shape == (6,)
    assert np.isfinite(obs).all()
    assert isinstance(reward, float)
    assert isinstance(terminated, bool)
    assert isinstance(truncated, bool)

    # This test model always predicts class 1.
    assert info["prediction"] == 1
    assert reward == pytest.approx(-5.0 - 0.001 * 100.0)
    assert terminated is False
    assert truncated is False


def test_action_is_clipped_to_action_space(env):
    env.reset(seed=0)

    action = np.array([-100.0, 5000.0, 99.0], dtype=np.float32)
    _, _, _, _, info = env.step(action)

    assert info["jitter"] == pytest.approx(0.0)
    assert info["padding"] == pytest.approx(1000.0)
    assert info["header_variant"] == 3

    assert env.current_sample["HeaderVariant"] == 3


def test_episode_truncates_at_max_steps(env):
    env.reset(seed=0)

    for step in range(1, 4):
        _, _, terminated, truncated, info = env.step(
            np.array([0.0, 0.0, 0.0], dtype=np.float32)
        )

        assert info["step"] == step

        if step < 3:
            assert truncated is False
            assert terminated is False
        else:
            assert truncated is True
            assert terminated is False


def test_step_requires_three_action_values(env):
    env.reset(seed=0)

    with pytest.raises(ValueError, match=r"shape \(3,\)"):
        env.step(np.array([1.0, 2.0], dtype=np.float32))


def test_original_pool_sample_is_not_mutated(env, malicious_pool):
    original = {k: v for k, v in malicious_pool[0].items()}

    # Force reset to pick the first sample.
    env.current_idx = 0
    env.current_sample = env._copy_sample(malicious_pool[0])
    env.step_count = 0

    env.step(np.array([5.0, 100.0, 2.0], dtype=np.float32))

    assert malicious_pool[0] == original


def test_numeric_values_are_finite(env):
    env.reset(seed=0)

    env.current_sample["dur"] = np.nan
    env.current_sample["tot_pkts"] = np.inf
    env.current_sample["tot_bytes"] = -np.inf
    env.current_sample["src_bytes"] = 123.0

    obs = env._extract_features(env.current_sample)

    assert obs.shape == (6,)
    assert np.isfinite(obs).all()


def test_tot_pkts_feature_uses_tot_pkts_column(env):
    """
    Contract test derived from train_surrogate.ipynb.

    The surrogate was trained on:
        [dur, tot_pkts, tot_bytes, src_bytes, proto, state]

    Therefore observation index 1 must come from 'tot_pkts', not
    'tot_bytes'. This test is expected to FAIL against the current
    c2_evasion_env.py until that implementation bug is fixed.
    """
    sample = {
        "dur": 10.0,
        "tot_pkts": 42.0,
        "tot_bytes": 500.0,
        "src_bytes": 250.0,
        "proto": "tcp",
        "state": "CON",
    }

    obs = env._extract_features(sample)

    assert obs[1] == pytest.approx(42.0)
    assert obs[2] == pytest.approx(500.0)


def test_header_variant_is_rounded_and_clipped(env):
    env.reset(seed=0)

    cases = [
        (0.1, 0),
        (0.49, 0),
        (0.5, 1),
        (1.49, 1),
        (1.5, 2),
        (2.49, 2),
        (2.5, 3),
        (3.0, 3),
    ]

    for raw_value, expected in cases:
        env.reset(seed=0)
        _, _, _, _, info = env.step(
            np.array([0.0, 0.0, raw_value], dtype=np.float32)
        )
        assert info["header_variant"] == expected


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
