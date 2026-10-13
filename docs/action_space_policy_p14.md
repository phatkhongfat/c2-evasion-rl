# P14 policy addendum — non-split mechanisms (pre-registered)

**Frozen 2026-10-13, before any P14 probe or sweep existed.** This is the new
dated policy file required by `docs/action_space_policy.md` (frozen, not
editable). Evidence base: `docs/p14_denominator.md` (all measurements from
already-committed reports and rule text, none from mechanisms introduced here).

## D4 — Denominator by classtype (extends the frozen P2P exclusion)

A flow counts in the C2 threat-model denominator iff `baseline_alert` is true
and `baseline_sids` contains at least one SID whose `classtype` is
trojan/malware (e.g. `trojan-activity`). Excluded: `policy-violation` (the
frozen BitTorrent-DHT precedent generalised), scan/recon (`attempted-recon`,
`bad-unknown` ET SCAN). Classtype is rule-author metadata fixed before any
evasion measurement, so this stratification cannot be a moved goalpost.
Reports state BOTH the raw rate (x/120) and the threat-model rate (x/N).

## D5 — Endpoint bar v2 for HTTP query commands, citation-gated

Only if RFC 3986 §2.1–2.4 and PHP `parse_str`/`$_GET` behaviour are verified
through the grounded-citations ledger: the command of a bodyless HTTP GET is
the parsed key→value set of its query string (percent-decoded). The v1 bar
(`valid_evasion_endpoint`) is NEVER replaced; cells gain
`valid_evasion_endpoint_q` alongside. No citation ⇒ no bar v2 and the
mechanism is reported as endpoint-strict-fail.

## D6 — New mechanisms stay out of the env until measured

`query_param_prepend` (and any P14 mechanism) enters only
`eval_pipeline.mutate_client_only` + the byte-identical mirror in
`hidden_defender_env.apply_mech`. `Discrete(14)` is untouched until a full
sweep passes the admission rules of the frozen policy file.

## D7 — The endpoint parser must honour Content-Length (bug fix, not a bar change)

Diagnosed before any mechanism work (T0.2): the 2 FakeAV flows that fail the
endpoint bar under `http_header_case` fail because `_parse_http` treats
everything after the first CRLFCRLF as the body, while the client stream is a
pipelined pair of POSTs. Lower-casing header field names of BOTH requests is
RFC 7230 §3.2-correct and required for the rule to die on both, but v1's
command comparison then sees request 2 verbatim inside request 1's "body".
Fix: parse per request using Content-Length (RFC 7230 §3.3.3) and compare the
list of per-request commands. This applies uniformly to every mechanism and
both corpora; v1 results are kept for comparison, never rewritten.

## Scope conclusions frozen from rule text (T0.3)

- `2012533` (Virut, 4 v8 flows): content-chain on `list.php?c=` has literal
  slack → `query_param_prepend` candidate.
- `2014635` (Kazy TLS, 4 flows): byte_extract/byte_test on ClientHello length
  fields — protocol-fixed bytes, NO client-side slack. Split-only; reported as
  such, not counted against non-split coverage.
- `2016413` (DNS sinkhole, 29 flows): matches the RESOLVER's reply
  (`udp any 53 -> $HOME_NET`) — outside any bot-ownership model. Excluded
  from reachable coverage, reported separately.

→ v8 reachable non-split target: **4/4 Virut flows**. Anything else is
honestly reported as no-slack or out-of-model.
