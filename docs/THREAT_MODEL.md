# Threat model — who the attacker owns in evasion benchmarks

Every valid-evasion number in this repo is only meaningful under an explicit
statement of **which endpoint of the C2 session the attacker may rewrite**.
This file fixes the two supported models and labels every number in this repo
with one of them.

## Model `client` (default, conservative)

The attacker owns the **bot** (the C2 client).  Only the client's own packets
may be rewritten by a mechanism (`apply_mech(..., ownership="client")`).
The responder's (C2 server / peer) packets are **never mutated** — enforced by
`test_server_packets_are_never_mutated` in `tests/test_evaluation_fixes.py`.

Numbers under this model:
- honest eval (real Snort, byte-equality): **40.0 %** (16/40) @ `split16` policy
- structural ceiling (oracle `split8` on all flows): **57.5 %** (23/40)
  = 16/16 http + 7/24 neris.  The 17 unevadable neris flows have their first
  packet emitted by the *peer* carrying the raw DHT signature (ET P2P
  BitTorrent DHT, sid 2008581/2008583/2008585, `HOME_NET=any`) — the alert
  fires before the client can do anything, and the server side is off-limits.

## Model `both` (two-sided ownership)

The attacker owns **both endpoints** (bot + C2 server), matching the reality
that a C2 operator runs the server.  Mechanisms may rewrite packets on either
side (`ownership="both"`).  This does **not** relax the verdict bar: the same
strict two-stream byte-equality check
(`c2_semantics.bytes_equal_semantics`, guarding the client **and** the server
stream) filters out any mutation that breaks reassembled-byte equality — 215
of 560 swept cells were rejected this way (evaded but `semantics_ok=False`).

Numbers under this model:
- ceiling sweep (real Snort, 560 cells, `controls/ownership_ceiling_sweep.py`,
  report `snort_validation/reports/ceiling_ownership_both.json`): **100 %**
  (40/40) with `split8` — 16/16 http + **24/24 neris**, all `semantics_ok=True`.
- retrained PPO (40 epochs, real-Snort teacher, 3 seeds, honest eval,
  `snort_validation/reports/ppo_both_test_RS64_s{7,1337,42}.json`): **100.0 %**
  (40/40) for **every seed**, `semantics_breaks = 0`, baseline alerted 40/40,
  policy converged to `split8` on all flows.

## Wire-through (DRY)

One mutation path, one bar, for both reward and evaluation:
- `apply_mech(pkts, mech, client_ip, ownership)` — env + eval share it.
- `bytes_equal_semantics(original, mutated, client_ip)` — guards both streams;
  `semantics_intact()` in the env delegates to it, so the PPO reward runs under
  the exact same bar the honest eval applies (Fix-3 invariant).

## CLI surface

`--ownership client|both` on `train_hidden_defender_ppo.py`,
`eval_fixed_pipeline.py`, and `ownership_ceiling_sweep.py`.  Default is
`client`; nothing changes unless the flag is passed explicitly.