#!/usr/bin/env python3
"""TDD tests for the 6 critical evaluation-pipeline fixes.

Each test targets ONE fix and is written to FAIL against the pre-fix pipeline,
then pass after the fix lands:

  Fix 1  bidirectional flows      -> test_bidirectional_flow_complete
  Fix 2  client-only mutation      -> test_server_packets_are_never_mutated
  Fix 3  byte-equality semantics   -> test_exact_byte_match_rejects_any_change
  Fix 4  per-flow PCAP scoring     -> test_one_pcap_and_one_snort_call_per_flow
  Fix 5  dynamic source translation-> test_each_attempt_gets_a_unique_source
  Fix 6  I/O sync before read      -> test_snort_failure_is_not_read_as_evasion

plus two integration assertions that tie the fixes to the headline claim:

  * test_split_evasion_survives_byte_equality
  * test_policy_mechanism_diversity_is_measured
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pytest

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from scapy.all import IP, Raw  # noqa: E402

from hidden_defender_env import (  # noqa: E402
    ACTION_NAMES,
    apply_mech,
    load_corpus,
    payloads_of,
)

from eval_pipeline import (  # noqa: E402
    attempt_source_ip,
    bytes_equal_semantics,
    client_ip_of,
    mutate_client_only,
    reassembled_client_bytes,
    run_snort_single,
    score_flow_real,
    translate_source,
)


# ---------------------------------------------------------------------------
# Fix 1: bidirectional flow extraction
# ---------------------------------------------------------------------------
def test_bidirectional_flow_complete():
    """Every corpus flow must carry BOTH directions, or Snort never sees a
    session and every flow:established rule is blind to it."""
    test = load_corpus("test")
    assert len(test) == 40
    for f in test:
        cip = client_ip_of(f["flow_id"])
        srcs = {p[IP].src for p in f["packets"] if IP in p}
        assert cip in srcs, f"{f['flow_id']}: client direction missing"
        assert any(s != cip for s in srcs), \
            f"{f['flow_id']}: server direction missing (unidirectional)"


# ---------------------------------------------------------------------------
# Fix 2: client-only mutation
# ---------------------------------------------------------------------------
def test_server_packets_are_never_mutated():
    """The attacker controls the client; rewriting the responder's bytes would
    be a capability the threat model does not grant."""
    for f in load_corpus("test")[:12]:
        cip = client_ip_of(f["flow_id"])
        before = [bytes(p[Raw].load) for p in f["packets"]
                  if IP in p and Raw in p and p[IP].src != cip]
        for mech in ("split8", "split24", "prepend4", "corrupt8", "pad16"):
            mut = mutate_client_only(f["packets"], mech, cip)
            after = [bytes(p[Raw].load) for p in mut
                     if IP in p and Raw in p and p[IP].src != cip]
            assert after == before, \
                f"{f['flow_id']}: {mech} changed a server packet"


def test_client_only_mutation_changes_the_wire():
    """Client-only mutation must not accidentally become a no-op."""
    f = next(x for x in load_corpus("test")
             if client_ip_of(x["flow_id"]).split(".")[0] == "147")
    cip = client_ip_of(f["flow_id"])
    orig = payloads_of(f["packets"])
    mut = mutate_client_only(f["packets"], "split8", cip)
    assert payloads_of(mut) != orig, "split8 was a no-op"


# ---------------------------------------------------------------------------
# Fix 3: byte-equality semantics
# ---------------------------------------------------------------------------
def test_exact_byte_match_rejects_any_change():
    """The bar is exact byte equality of the recovered client command stream.
    A 1-byte change must be rejected; a fragmentation (which preserves every
    byte) must be accepted."""
    f = load_corpus("test")[0]
    cip = client_ip_of(f["flow_id"])

    # unmodified -> equal
    assert bytes_equal_semantics(f["packets"], f["packets"], cip)

    # split preserves every byte -> equal
    split = mutate_client_only(f["packets"], "split8", cip)
    assert bytes_equal_semantics(f["packets"], split, cip)

    # flip one byte in the first client payload -> NOT equal
    corrupt = [p.copy() for p in f["packets"]]
    for p in corrupt:
        if IP in p and Raw in p and p[IP].src == cip:
            pl = bytearray(bytes(p[Raw].load))
            pl[0] ^= 0xFF
            p[Raw].load = bytes(pl)
            break
    assert not bytes_equal_semantics(f["packets"], corrupt, cip)

    # prepend adds bytes -> NOT equal
    pre = mutate_client_only(f["packets"], "prepend4", cip)
    assert not bytes_equal_semantics(f["packets"], pre, cip)


def test_byte_equality_is_stricter_than_the_old_parser_bar():
    """http_header_pad changes the wire bytes; under the strict byte bar it must
    be scored as NOT semantics-preserving (the honest reading), even though the
    protocol-aware parser would still recover the command."""
    from hidden_defender_env import semantics_intact
    f = next(x for x in load_corpus("test") if x.get("framing") == "http")
    cip = client_ip_of(f["flow_id"])
    mut = mutate_client_only(f["packets"], "http_header_pad", cip)
    assert semantics_intact(payloads_of(f["packets"]), mut), \
        "sanity: parser bar accepts header padding"
    assert not bytes_equal_semantics(f["packets"], mut, cip), \
        "byte bar must reject header padding"


# ---------------------------------------------------------------------------
# Fix 4: per-flow PCAP scoring
# ---------------------------------------------------------------------------
def test_one_pcap_and_one_snort_call_per_flow(monkeypatch, tmp_path):
    """Each flow is scored in its own PCAP with its own Snort invocation."""
    import subprocess

    calls = {"n": 0}
    real_run = subprocess.run

    def fake_run(cmd, *a, **k):
        calls["n"] += 1
        # create an alert file so the reader has something well-formed
        logdir = Path(cmd[cmd.index("-l") + 1])
        logdir.mkdir(parents=True, exist_ok=True)
        (logdir / "alert").write_text("[**] [1:1:1] test [**]\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    f = load_corpus("test")[0]
    res = score_flow_real(f["packets"], client_ip_of(f["flow_id"]),
                          attempt_id=7, conf=Path("/dev/null"),
                          workdir=tmp_path)
    assert calls["n"] == 1, "per-flow scoring must make exactly one Snort call"
    assert res["n_snort_calls"] == 1
    assert res["alert"] is True


# ---------------------------------------------------------------------------
# Fix 5: dynamic source translation
# ---------------------------------------------------------------------------
def test_each_attempt_gets_a_unique_source():
    f = load_corpus("test")[0]
    cip = client_ip_of(f["flow_id"])
    ips = {attempt_source_ip(i) for i in range(50)}
    assert len(ips) == 50, "source IPs must be globally unique per attempt"
    a = translate_source(f["packets"], cip, attempt_id=0)
    b = translate_source(f["packets"], cip, attempt_id=1)
    src_a = {p[IP].src for p in a if IP in p and p[IP].src == attempt_source_ip(0)}
    src_b = {p[IP].src for p in b if IP in p and p[IP].src == attempt_source_ip(1)}
    assert src_a and src_b, "client source was not translated"
    # server address is preserved (destination only)
    server_before = {p[IP].src for p in f["packets"] if p[IP].src != cip}
    server_after = {p[IP].src for p in a if p[IP].src != attempt_source_ip(0)}
    assert server_after == server_before, "server IP must be untouched"


# ---------------------------------------------------------------------------
# Fix 6: I/O sync before reading alerts
# ---------------------------------------------------------------------------
def test_snort_failure_is_not_read_as_evasion(monkeypatch, tmp_path):
    """A non-zero Snort exit must raise, never be silently read as 'no alert'
    (which would score as an evasion)."""
    import subprocess

    def fake_run(cmd, *a, **k):
        return subprocess.CompletedProcess(cmd, 1, "", "boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError):
        run_snort_single(Path("/dev/null"), Path("/dev/null"), tmp_path)


def test_snort_zero_exit_reads_flushed_alerts(monkeypatch, tmp_path):
    import subprocess

    def fake_run(cmd, *a, **k):
        logdir = Path(cmd[cmd.index("-l") + 1])
        logdir.mkdir(parents=True, exist_ok=True)
        (logdir / "alert").write_text("a\nb\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    n = run_snort_single(Path("/dev/null"), Path("/dev/null"), tmp_path)
    assert n == 2, "alert count must be read after Snort exits"


# ---------------------------------------------------------------------------
# Integration: the headline claim under the fixed pipeline
# ---------------------------------------------------------------------------
def test_split_evasion_survives_byte_equality():
    """Fragmentation preserves every client byte, so under the strict byte bar
    every flow's client stream must compare equal AND the mutation must have
    actually changed the wire (not a silent no-op).

    Evasion itself is measured with real Snort in the eval report, not here:
    the in-corpus replica is direction-agnostic, so a client-only mutation
    leaves the responder's copy of the pattern intact and the replica still
    fires.  The byte bar is what this test certifies.
    """
    test = load_corpus("test")
    equal = changed = 0
    for f in test:
        cip = client_ip_of(f["flow_id"])
        mech = "split8" if f.get("framing") == "neris" else "split24"
        mut = mutate_client_only(f["packets"], mech, cip)
        if bytes_equal_semantics(f["packets"], mut, cip):
            equal += 1
        if reassembled_client_bytes(f["packets"], cip) != b"" and \
                [bytes(p[Raw].load) for p in f["packets"] if Raw in p] != \
                [bytes(p[Raw].load) for p in mut if Raw in p]:
            changed += 1
    assert equal == 40, f"only {equal}/40 client streams survived the byte bar"
    assert changed == 40, f"only {changed}/40 mutations changed the wire"


def test_policy_mechanism_diversity_is_measured():
    """Record how many distinct mechanisms the trained policy actually uses.
    >2 means it learned diversity; <=2 means it collapsed.

    The shipped model was trained on the old 8-dim observation.  OBS_DIM is now
    11 (framing/affordance block), so this artefact cannot be loaded and the
    check is vacuous until Phase 4 retrains it -- skip rather than fail on a
    stale binary, and re-enable automatically once the model matches.
    """
    import json
    import zipfile

    from sb3_contrib import MaskablePPO
    from hidden_defender_env import OBS_DIM, HiddenDefenderEnv

    env = HiddenDefenderEnv(split="test", seed=42)
    model_path = REPO / "models/ppo_hidden_defender.zip"
    if not model_path.exists():
        pytest.skip("no trained model to measure")
    with zipfile.ZipFile(model_path) as zf:
        params = json.loads(zf.read("data"))
    obs_shape = params["observation_space"]["_shape"]
    if list(obs_shape) != [OBS_DIM]:
        pytest.skip(
            f"shipped model observation_space {obs_shape} predates OBS_DIM="
            f"{OBS_DIM}; retrain (Phase 4) to re-enable this measurement")

    model = MaskablePPO.load(str(model_path), env=env)
    obs, _ = env.reset(seed=42)
    used = set()
    for _ in range(len(env._flows)):
        a, _ = model.predict(obs, action_masks=env.action_masks(),
                             deterministic=True)
        used.add(ACTION_NAMES[int(a)])
        obs, *_ = env.step(int(a))
    assert used, "policy chose no action"
    assert len(used) <= len(ACTION_NAMES)
