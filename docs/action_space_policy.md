# Action-space admission and removal policy (pre-registered)

**Frozen 2026-10-13, before any Phase 1 sweep under this policy existed.**
Pinned at this commit; nothing below may be edited after the first sweep that
reports an A1-A4 or R1-R3 value. Any change must be a new dated policy file.

Purpose: `headroom = oracle - best_single` has been measured as 0 under five
different framings (P7-P11). Before looking at more numbers, state in advance
exactly what would make the action space larger or smaller. A policy written
after the results is not a policy.

## Reference configuration

All numbers below mean, unless stated otherwise:

- test split, 40 flows, `ownership=both`, real Snort **2.9.20 GRE (Build 82)**
- conf `snort_validation/et_open_c2/snort_et_c2_nop2p.conf` — ET Open C2 rules
  with the 102 `classtype:policy-violation` BitTorrent DHT rules removed (P11)
- bars: `valid_evasion` (byte equality, unchanged) **and**
  `valid_evasion_endpoint` (endpoint-command equivalence, new). A mechanism is
  judged on both; the second bar never replaces the first.

## Denominator: flows with something to evade

Measured on the nop2p conf (P11.6): `baseline_sids` contains **only SID 2012627**
and `baseline_alert` is true on **16 of 40** flows. The other 24 (`neris`) are
silent under the C2-only ruleset.

Every rate in this document is therefore over the **detected** flows, N=16 on
the nop2p conf, N=40 on the full ruleset. A flow with nothing to evade cannot
contribute to an evasion benchmark: it inflates `oracle` and `best_single` by
the same amount and makes `noop` look like a winning mechanism.

`controls/rl_headroom.py --require-baseline` (default on) enforces this by
dropping cells with a falsy `baseline_alert` and reporting
`flows_dropped_no_baseline`.

## Admission

A mechanism may enter `ACTION_NAMES` only if, on the test split under
`ownership=both` with real Snort, it satisfies **all** of:

- **A1** `evaded > 0` on at least one detected flow — it defeats something real.
- **A2** `endpoint_ok` is True on >= 90 % of the flows where `evaded` is True —
  the evasion is non-vacuous: a real handler still reads the same command.
- **A3** **control sanity**: on the same run, `noop` has `evaded == False` on
  every detected flow (0 of N). If the control breaks, the whole run is void
  and is re-run. *This is the rule as it must be measured — not `noop` evades
  0/40, which is unachievable by construction on the nop2p conf and would void
  every run for a reason that has nothing to do with the candidate.*
- **A4** no regression: it does not reduce `split8` or `split_slow` below their
  current `valid_evasion` on any framing.

## Removal

A mechanism is dropped when **any** of:

- **R1** vacuous under **both** bars (`sem_ok == 0` **and** `endpoint_ok == 0`
  on every flow);
- **R2** `evaded == 0` everywhere;
- **R3** `mech_applicable` is False on > 50 % of flows **and** it never wins.

## Anti-gaming clause

No mechanism with `valid_evasion > 0` **or** `valid_evasion_endpoint > 0` on any
flow may be removed, in any revision of this policy. `split8` and `split_slow`
are therefore structurally protected.

This exists because the cheap way to manufacture a positive `headroom` is to
delete the mechanism that already wins 16/16. That is a rigged benchmark, not a
finding, and it is the one failure mode this document is written to prevent.

No criterion may be added after the first sweep under this policy. Only the
verdict tables get appended.

## What this policy does NOT promise

It does not promise `headroom > 0`. On every measurement so far (P7-P11.6)
`headroom = 0`: every mechanism that survives both bars wins on the same
detected flows that fragmentation wins on. The honest outcome of Phase 1 may be
that the action space grows and the headroom stays zero — and per
arXiv:2505.01328 that is not a null result, it is the expected result, reported
at the packet level against real Snort rather than in feature space against a
learned classifier.

## Predictions registered before the sweep

Recorded so the sweep can falsify them rather than explain them:

- **D1** `http_header_case` reaches `evaded = 16/16` on the detected flows,
  because ET Open SID 2012627 matches `Accept|3a 20|` case-sensitively inside a
  4-content `distance:0` chain. *Falsified if `evaded` < 16 or if SID 2012627
  still fires.*
- **D2** `http_header_case` has `endpoint_ok = 16/16`, because folding a field
  NAME is legal under RFC 7230 s3.2 and leaves the body byte-identical.
  *Falsified by any `endpoint_ok == False`.*
- **D3** `headroom` stays 0 under both bars. *Falsified by `headroom > 0`.*

D1 is a property of the ET Open signature, not a general technique, and must be
described that way wherever it is reported.