# P15 policy addendum — post-P14 action space (pre-registered)

**Frozen 2026-10-13, before any P15 code change.** This is the new dated policy
file required by `docs/action_space_policy.md` (frozen, not editable) and it
extends `docs/action_space_policy_p14.md` (frozen D4–D7). Nothing below may be
edited after the first P15 code commit; any change must be a new dated file.

Evidence base — all numbers below come from reports already committed at HEAD
`292ae06`, none from a P15 run:

- `snort_validation/reports/ceiling_v6_case_fullrules_qbar.json` — `http_header_case`,
  40 test flows, real Snort (conf 21k `et_open_c2`).
- `snort_validation/reports/p13_v9_query_prepend.json` — `query_param_prepend`,
  5 HTTP flows of the extended corpus, real Snort (ET Open 3.0.0, 52 454 rules).
- `snort_validation/reports/p14_v10_qpp_old_corpus.json` — `query_param_prepend`,
  40 test flows of the old corpus, real Snort (conf 21k).
- `snort_validation/reports/p13_v7_noop.json` — `noop` control, 120 extended
  test flows, real Snort.
- `snort_validation/reports/control_noop_real_snort.json` — `noop` control,
  40 old-corpus test flows, real Snort.

## D8 — Reward-bar alignment (the training semantics gate)

The training reward's semantics gate becomes the **union of the frozen headline
bars**:

```
semantics_ok_reward = bytes_equal_semantics        (v1 byte bar)
                      ∨ endpoint_commands_preserved (D7)
                      ∨ endpoint_query_preserved     (D5)
```

D7 and D5 are the bars frozen in `docs/action_space_policy_p14.md` **before any
P14 probe existed** and are citation-gated (RFC 3986 §2.1–2.4 / PHP `parse_str`
for D5; RFC 7230 §3.2/§3.3.3 for D7). Rationale: the reward must not be
**stricter** than the headline validity definition, or the policy can never
represent a mechanism already measured to win. A mechanism that changes the
wire on purpose (as both P14 mechanisms do) is scored as a semantics break by
the byte bar alone, so the byte-only gate drove the reward to `-10` on exactly
the mechanisms the evaluation counts as valid.

Rules:

- **Uniform across every mechanism** — no per-mechanism special-casing. A gate
  that names a mechanism is not a gate.
- D7/D5 are HTTP-only and **fail-closed** on non-HTTP payloads, so `neris`/`dns`
  flows fall back to the byte bar exactly as before; the relaxation cannot leak.
- `corrupt8` / `length_wrapper` / `prepend*` still fail: on the 40 old-corpus
  test flows `corrupt8` is 0/0/0 and `prepend*` 0/0/0 across
  (byte, D7, D5), so the union is False. The gate is not a blanket pass.
- The byte-bar verdict is still reported verbatim everywhere. `step()` exposes
  it as `info["semantics_bytes"]`, so no table loses the strict number; the
  relaxation affects the reward and the A2 admission reading only.

### Correction vs. the P15 plan draft

The plan draft wrote the gate as `bytes ∨ (D7 ∧ D5)`. That conjunction is
**inconsistent with the plan's own evidence and with T1.3**: `query_param_prepend`
is D7=False, D5=True (it rewrites the request line by design), so `D7 ∧ D5` is
False and the mechanism the whole P15 cycle exists to admit would score as a
semantics break. The frozen rule is therefore the **disjunction** of the frozen
bars. This matches `docs/p14_cost_headroom.md`, which states plainly that only D5
"nói đúng handler thật vẫn đọc được cùng một lệnh" for `query_param_prepend`,
while v1 and D7 fail it by design.

## D9 — Admission bar-group (reading A2 of the frozen policy)

A2 of `docs/action_space_policy.md` ("`endpoint_ok` is True on ≥ 90 % of the
flows where `evaded` is True") is read as: **under any frozen endpoint bar**
(`v1 ∨ D7 ∨ D5`), the mechanism clears 90 %. A literal v1-only reading would
permanently exclude `query_param_prepend` (v1 fails it by design) and make it
impossible to train a mechanism already measured to win 4/4 on the Virut flows.

This is a **rule-group interpretation, not a name-based exception**. It is
grounded in the already-measured A1–A4 evidence:

- **A1 (defeats something real).** `http_header_case` evaded 16/16 old-corpus C2
  flows (`ceiling_v6_case_fullrules_qbar.json`); `query_param_prepend` evaded
  4/4 Virut flows (`p13_v9_query_prepend.json`).
- **A2 (non-vacuous).** `query_param_prepend` passes D5 on 4/4 flows it evades;
  `http_header_case` passes D7 16/16 and D5 16/16 on the flows it evades.
- **A3 (control sanity).** `noop` evaded 0/115 detected flows
  (`p13_v7_noop.json`) and 0/40 old-corpus flows
  (`control_noop_real_snort.json`); alert rate 100 %.
- **A4 (no regression).** The two mechanisms are appended to `ACTION_NAMES`;
  no split branch is touched, so `split8`/`split_slow` coverage cannot drop.
  Pinned by a test (T1.5).

The byte bar is never replaced: `valid_evasion` keeps its meaning and is
reported alongside.

## D10 — Costs (anchored to measured wire cost)

Appended to `ACTION_COSTS` (old indices 0–14 unchanged):

```python
15: 0.05,    # http_header_case   (Δwire = 0 B; cheap, natural)
16: 0.05,    # query_param_prepend (+4..8 B / flow, 0 fragments)
```

Both are in the same band as `http_header_pad` (0.05) and below every split
(0.40–0.65). Anchor: measured wire cost in `docs/p14_results.md` /
`docs/p14_cost_headroom.md` (`query_param_prepend` +4…+8 B and **0 fragments** vs
`split8` +245 B/flow). `PROTOCOL_APPROPRIATE["http"]` gains both names; the
existing protocol-match bonus is gated on a real valid evasion and cannot
manufacture one.

**Anti-reward-hacking commitment.** Costs are frozen here and will **not** be
re-tuned after seeing training results. If the policy still collapses onto split
on the old corpus, that is reported as a finding (D10 does not change).

## Scope

P15 widens `Discrete(15)` → `Discrete(17)` and aligns the reward gate per D8.
Old checkpoints (`Discrete(15)`) will not load into the 17-action env; that is
accepted (retraining is the goal), and no version-switch is added. This is the
admission step that `docs/action_space_policy_p14.md` D6 deferred ("`Discrete(14)`
untouched until a full sweep passes the admission rules"): the P14.3 sweep and
the v10 report supply that sweep.
