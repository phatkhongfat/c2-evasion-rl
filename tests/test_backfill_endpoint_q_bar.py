"""D7 backfill: endpoint_q (per-request, CL-aware) verdict on existing sweeps.

The q-bar reuses the SAME (original, mutation) pair as v1 -- the byte-identity
guarantee proven in test_backfill_endpoint_bar.py therefore covers it -- but it
must be computed with endpoint_commands_preserved, written under its own keys,
and never alter v1's keys.  Also proves --corpus reaches HiddenDefenderEnv
(the v8 report was swept on corpus_p13_extended.pkl, not the default corpus).
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for sub in ("controls", "snort_validation", "ai_agent"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

import backfill_endpoint_bar as bf                           # noqa: E402
from hidden_defender_env import HiddenDefenderEnv            # noqa: E402


@pytest.fixture(scope="module")
def env_and_http_flow():
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    for f in env._flows:
        if f.get("framing") == "http":
            return env, f
    raise AssertionError("no http flow in the test split")


@pytest.fixture(autouse=True)
def _no_snort(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("backfill must NOT run Snort")
    monkeypatch.setattr("eval_pipeline._run_snort", boom)


def _report(env_and_http_flow, mech="http_header_case"):
    env, f = env_and_http_flow
    return {
        "ownership": "both", "split": "test", "scorer": "real_snort",
        "bar": "two_stream_byte_equality", "n_flows": 1,
        "cells": [{"flow_id": f["flow_id"], "framing": "http", "mech": mech,
                   "baseline_alert": True, "evaded": True,
                   "semantics_ok": True, "valid_evasion": True,
                   "valid_evasion_endpoint": True,
                   "sids": [], "baseline_sids": [2012627]}],
    }, env


def test_backfill_adds_q_keys_without_touching_v1(env_and_http_flow):
    rep, env = _report(env_and_http_flow)
    before = dict(rep["cells"][0])
    out = bf.backfill(rep, env)
    c = out["cells"][0]
    assert "endpoint_q_ok" in c and "valid_evasion_endpoint_q" in c
    # v1 keys byte-identical to the input
    assert c["valid_evasion_endpoint"] == before["valid_evasion_endpoint"]
    assert c["evaded"] == before["evaded"]
    # q verdict equals a direct call on the same mutation
    from eval_pipeline import client_ip_of, mutate_client_only
    from c2_semantics import endpoint_commands_preserved
    f = [x for x in env._flows if x["flow_id"] == c["flow_id"]][0]
    cip = client_ip_of(c["flow_id"])
    mut = mutate_client_only(f["packets"], "http_header_case", cip,
                             ownership="both")
    direct = endpoint_commands_preserved(f["packets"], mut, cip)
    assert c["endpoint_q_ok"] == direct
    assert c["valid_evasion_endpoint_q"] == (direct and c["evaded"])


def test_q_bar_sees_the_same_bytes_as_v1(env_and_http_flow, monkeypatch):
    """The mutation pair handed to both bars must be identical objects/bytes."""
    rep, env = _report(env_and_http_flow)
    seen_v1, seen_q = {}, {}
    real_v1 = bf.endpoint_command_preserved
    real_q = bf.endpoint_commands_preserved

    def spy_v1(orig, mut, cip):
        seen_v1["bytes"] = [bytes(p) for p in mut]
        return real_v1(orig, mut, cip)

    def spy_q(orig, mut, cip):
        seen_q["bytes"] = [bytes(p) for p in mut]
        return real_q(orig, mut, cip)

    monkeypatch.setattr(bf, "endpoint_command_preserved", spy_v1)
    monkeypatch.setattr(bf, "endpoint_commands_preserved", spy_q)
    bf.backfill(rep, env)
    assert seen_v1["bytes"] == seen_q["bytes"]


def test_baseline_cell_gets_q_verdict_too(env_and_http_flow):
    rep, env = _report(env_and_http_flow, mech=None)
    rep["cells"][0]["mech"] = None
    out = bf.backfill(rep, env)
    c = out["cells"][0]
    assert c["endpoint_q_ok"] is True   # identity mutation preserves commands
    assert c["valid_evasion_endpoint_q"] == bool(c["evaded"])


def test_corpus_arg_reaches_env(monkeypatch, tmp_path):
    calls = {}

    class FakeEnv:
        _flows = []

    def fake_ctor(**kw):
        calls.update(kw)
        return FakeEnv()

    monkeypatch.setattr(bf, "HiddenDefenderEnv", fake_ctor)
    rep = tmp_path / "rep.json"
    rep.write_text(json.dumps({"ownership": "both", "cells": []}))
    rc = bf.main([str(rep), "--out", str(tmp_path / "x.json"),
                  "--corpus", "/tmp/corpus.pkl"])
    assert rc == 0
    assert calls.get("corpus") == "/tmp/corpus.pkl"
