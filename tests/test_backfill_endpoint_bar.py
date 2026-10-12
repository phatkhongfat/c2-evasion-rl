"""T7 (P12): backfill the endpoint-command verdict onto an EXISTING sweep.

The risk this file exists to close: ``backfill_endpoint_bar`` recomputes the
mutation locally and ASSUMES it is byte-identical to what the sweep already fed
to Snort.  If the sweep used a different mutation path, ownership default or
framing, then ``endpoint_ok`` would be computed on bytes Snort never saw and the
whole dual-bar table would be quietly wrong.  ``test_backfill_scores_the_
same_bytes_the_sweep_fed_snort`` proves the assumption by capturing the exact
packets backfill hands to the bar and comparing them, byte for byte, with the
mutation ``score_flow_real`` performs for the sweep.

No Snort is run: ``_run_snort`` is monkeypatched to raise, so any accidental
engine call fails loudly.
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

from eval_pipeline import client_ip_of, mutate_client_only  # noqa: E402
from hidden_defender_env import HiddenDefenderEnv            # noqa: E402
import backfill_endpoint_bar as bf                           # noqa: E402

CIP, SIP = "10.0.0.1", "10.0.0.9"


@pytest.fixture(scope="module")
def env_and_http_flow():
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    for f in env._flows:
        if f.get("framing") == "http":
            return env, f
    raise AssertionError("no http flow in the test split")


def _cell(fid, mech, **over):
    c = {"flow_id": fid, "framing": "http", "mech": mech,
         "baseline_alert": True, "evaded": True, "semantics_ok": True,
         "valid_evasion": True, "sids": [], "baseline_sids": [2012627]}
    c.update(over)
    return c


def _report(cells, **over):
    r = {"ownership": "both", "split": "test", "scorer": "real_snort",
         "bar": "two_stream_byte_equality", "n_flows": 40, "cells": cells}
    r.update(over)
    return r


@pytest.fixture(autouse=True)
def _no_snort(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("backfill must NOT run Snort")
    monkeypatch.setattr("eval_pipeline._run_snort", boom)


def test_backfill_scores_the_same_bytes_the_sweep_fed_snort(
        env_and_http_flow, monkeypatch):
    """THE load-bearing check: byte-identity of the recomputed mutation.

    Capture the (original, mutation) pair backfill passes to the bar and assert
    it equals the mutation ``score_flow_real`` builds for the sweep:
    ``mutate_client_only([p.copy() for p in packets], mech, cip,
    ownership=report["ownership"])``.
    """
    env, f = env_and_http_flow
    fid, cip = f["flow_id"], client_ip_of(f["flow_id"])
    seen = {}
    real = bf.endpoint_command_preserved

    def spy(orig, mut, client_ip):
        seen["orig"] = [bytes(p) for p in orig]
        seen["mut"] = [bytes(p) for p in mut]
        seen["cip"] = client_ip
        return real(orig, mut, client_ip)

    monkeypatch.setattr(bf, "endpoint_command_preserved", spy)

    for mech in ("split8", "split_slow", "http_header_pad", "noop", "pad16"):
        seen.clear()
        bf.backfill(_report([_cell(fid, mech)]), env, "test")

        # the sweep's path, verbatim (eval_pipeline.score_flow_real lines 464-469)
        orig = [p.copy() for p in f["packets"]]
        sweep_mut = mutate_client_only(orig, mech, cip, ownership="both")

        assert seen["cip"] == cip
        assert seen["orig"] == [bytes(p) for p in orig], (
            f"{mech}: backfill did not score the ORIGINAL the sweep used")
        assert seen["mut"] == [bytes(p) for p in sweep_mut], (
            f"{mech}: backfill recomputed DIFFERENT bytes than the sweep fed "
            f"to Snort -- the endpoint verdict is not about Snort's bytes")


def test_backfill_defaults_ownership_to_both_not_client(
        env_and_http_flow, monkeypatch):
    """A report with no ``ownership`` key must default to 'both' (the sweep's
    default), NOT mutate_client_only's 'client' default."""
    env, f = env_and_http_flow
    fid = f["flow_id"]
    cip = client_ip_of(fid)
    captured = {}
    real = bf.endpoint_command_preserved

    def spy(orig, mut, client_ip):
        captured["mut"] = [bytes(p) for p in mut]
        return real(orig, mut, client_ip)

    monkeypatch.setattr(bf, "endpoint_command_preserved", spy)
    r = _report([_cell(fid, "split8")])
    r.pop("ownership")
    bf.backfill(r, env, "test")

    orig = [p.copy() for p in f["packets"]]
    both = [bytes(p) for p in mutate_client_only(orig, "split8", cip,
                                                 ownership="both")]
    assert captured["mut"] == both


def test_backfill_copies_snort_fields_verbatim(env_and_http_flow):
    env, f = env_and_http_flow
    fid = f["flow_id"]
    src = _report([_cell(fid, "split8", alert=False, evaded=True,
                         sids=[], baseline_sids=[2012627, 1])])
    out = bf.backfill(src, env, "test")
    assert len(out["cells"]) == 1
    x, y = src["cells"][0], out["cells"][0]
    for k in ("alert", "evaded", "sids", "baseline_sids", "baseline_alert",
              "semantics_ok", "valid_evasion"):
        assert y[k] == x[k], f"Snort-derived field {k} was mutated"


def test_backfill_adds_both_endpoint_keys(env_and_http_flow):
    env, f = env_and_http_flow
    fid = f["flow_id"]
    out = bf.backfill(_report([_cell(fid, "http_header_pad")]), env, "test")
    c = out["cells"][0]
    assert "endpoint_ok" in c and "valid_evasion_endpoint" in c
    # http_header_pad: command preserved -> endpoint_ok True
    assert c["endpoint_ok"] is True
    assert c["valid_evasion_endpoint"] is True


def test_valid_evasion_endpoint_requires_evaded(env_and_http_flow):
    env, f = env_and_http_flow
    fid = f["flow_id"]
    out = bf.backfill(_report([_cell(fid, "http_header_pad", evaded=False,
                                     valid_evasion=False)]), env, "test")
    c = out["cells"][0]
    assert c["endpoint_ok"] is True
    assert c["valid_evasion_endpoint"] is False


def test_backfill_does_not_mutate_input_and_never_edits_it(env_and_http_flow):
    env, f = env_and_http_flow
    fid = f["flow_id"]
    src = _report([_cell(fid, "split8")])
    before = json.dumps(src, sort_keys=True)
    out = bf.backfill(src, env, "test")
    assert json.dumps(src, sort_keys=True) == before, "input report was mutated"
    assert out is not src
    assert out["cells"][0] is not src["cells"][0]


def test_backfill_records_which_bar_it_added(env_and_http_flow):
    env, f = env_and_http_flow
    out = bf.backfill(_report([_cell(f["flow_id"], "noop")]), env, "test")
    assert "endpoint_command_preserved" in out["bar_endpoint"]


def test_backfill_keeps_unknown_flow_cells_untouched(env_and_http_flow):
    """A cell whose flow is absent from the corpus must be passed through, not
    silently dropped (a missing flow would otherwise vanish from the table)."""
    env, f = env_and_http_flow
    out = bf.backfill(_report([_cell("no-such-flow", "split8")]), env, "test")
    assert len(out["cells"]) == 1
    assert "endpoint_ok" not in out["cells"][0]


def test_cli_writes_a_new_file_and_leaves_the_input_alone(tmp_path,
                                                          env_and_http_flow):
    """The tool must write a NEW file; the input report is never edited."""
    env, f = env_and_http_flow
    src = tmp_path / "in.json"
    dst = tmp_path / "out.json"
    src.write_text(json.dumps(_report([_cell(f["flow_id"], "http_header_pad")])))
    before = src.read_bytes()
    rc = bf.main([str(src), "--split", "test", "--out", str(dst)])
    assert rc == 0
    assert src.read_bytes() == before
    assert dst.exists()
    assert "endpoint_ok" in json.loads(dst.read_text())["cells"][0]


def test_http_header_pad_is_NOT_endpoint_safe_on_pipelined_requests(
        env_and_http_flow):
    """Measured limitation of ``http_header_pad`` (P12 T7), pinned here.

    The plan predicted ``valid(endpoint)=16`` for this mechanism on the 40-flow
    corpus; the measured value is 14.  Root cause: two corpus flows carry TWO
    pipelined HTTP requests in the client stream, and the pad mechanism inserts
    junk headers after EVERY request line.  ``endpoint_model._parse_http``
    treats everything after the FIRST header block as the command, so the
    second request (now preceded by junk headers) leaks into the recovered
    command and the endpoint bar correctly rejects it.

    This is a real limit of the mechanism, NOT a backfill error: backfill's
    recomputed mutation is byte-identical to the sweep's (see the identity
    test).  The synthetic flow below reproduces the shape without the corpus.
    """
    from c2_semantics import endpoint_command_preserved
    from scapy.all import Ether, IP, Raw, TCP
    from eval_pipeline import mutate_client_only
    req1 = (b"POST /getjson HTTP/1.1\r\nHost: a.com\r\nContent-Length: 4\r\n"
            b"\r\ndata=1")
    req2 = (b"POST /getjson HTTP/1.1\r\nHost: a.com\r\nContent-Length: 4\r\n"
            b"\r\ndata=2")
    orig = [Ether() / IP(src=CIP, dst=SIP)
            / TCP(sport=1234, dport=80, seq=1000, flags="PA") / Raw(req1),
            Ether() / IP(src=CIP, dst=SIP)
            / TCP(sport=1234, dport=80, seq=1000 + len(req1), flags="PA")
            / Raw(req2)]
    mut = mutate_client_only(orig, "http_header_pad", CIP, ownership="both")
    assert endpoint_command_preserved(orig, mut, CIP) is False


def test_single_request_http_header_pad_is_endpoint_safe():
    """The counterpart: on a single request the pad IS endpoint-safe."""
    from c2_semantics import endpoint_command_preserved
    from eval_pipeline import mutate_client_only
    from scapy.all import Ether, IP, Raw, TCP
    one = (b"POST /getjson HTTP/1.1\r\nHost: a.com\r\nContent-Length: 4\r\n"
           b"\r\ndata=1")
    orig = [Ether() / IP(src=CIP, dst=SIP)
            / TCP(sport=1234, dport=80, seq=1000, flags="PA") / Raw(one)]
    mut = mutate_client_only(orig, "http_header_pad", CIP, ownership="both")
    assert endpoint_command_preserved(orig, mut, CIP) is True
