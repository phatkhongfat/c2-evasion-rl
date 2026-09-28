# Surrogate-vs-Reality Audit

Measured 2026-09-28. All numbers below come from scripts in `controls/`, each of
which scored **identical mutated packets** through both the `RealRulesReplica`
surrogate and the real Snort 2.9.20 binary with the 21,374-rule ET Open C2 set.

## Why this had to be measured

This project's training signal comes from a surrogate, not from the real
defender. A surrogate that disagrees with reality in either direction invalidates
the policy: a *false safe* (surrogate says evade, Snort alerts) trains the policy
toward a mechanism that does not work, and is the failure mode that already forced
two retractions of a "16/16" claim earlier in the project.

## Setup

- Corpus: `snort_validation/reports/hidden_defender_corpus.pkl`, train split.
- Real defender: Snort 2.9.20, `snort_validation/et_open_c2/`, `batch_size=1`
  (one Snort process per flow, so fragment-level alerts are not lost to batching).
- The sweep covers **all 14 mechanisms x 16 flows = 224 cells**, each one real
  Snort invocation at ~11 s.

## Result 1 — the bias is one-sided

| population | agreement | false-safe |
|---|---|---|
| all 224 cells | 161 (71.9%) | **0** |
| cells the policy can actually choose (semantics-preserving, not masked) | 103/116 (88.8%) | **0** |

All **63 disagreements point the same way**: the replica alerts where real Snort
does not. Not one points the other way.

**This is the load-bearing result.** The surrogate is *pessimistic*, not
unfaithful. It never tells the policy a mechanism is safe when Snort fires, so
anything the surrogate-scored policy learns to evade genuinely evades. The gap
biases the search rather than corrupting it.

Practical consequence: a policy trained against this surrogate does **not** need
every number re-verified merely because the scorer was the surrogate. Verifying
the *direction* of the bias is sufficient, and it was verified over 224 calls.

## Result 2 — the bias is not free

`split8` is a genuine evasion on real Snort that the surrogate refuses to credit,
on **11 of 16 HTTP flows**:

| | flows with >=1 evading eligible mechanism |
|---|---|
| real Snort | 16/16 (100%) |
| surrogate-visible | 15/16 (93.8%) |

The visible ceiling is capped below reality. This is the mechanistic explanation
for the query gap measured earlier: PPO needed 704 queries where the greedy
baseline needed 149, because the surrogate makes the problem look harder than it
is, so the policy must search longer to find what the real defender would have
given away.

## Result 3 — the 20.6% unimplemented-rule gap stayed closed here

The replica cannot implement 4,394 of the 21,374 rules (20.6%): anything using
`pcre`, `byte_test`, `byte_extract` or `byte_jump`. Those are dropped silently. If
any of them fired on a mutated flow, the replica would wrongly report "no alert".

Across 224 real Snort calls spanning all 14 mechanisms, this never happened: zero
false-safe. For this corpus the concern is closed empirically — but only for these
16 flows, and it is not evidence the gap can never bite on other traffic.

## Result 4 — reduced-run agreement

Training the actual PPO on 16 flows for 1 epoch scored both ways:

| scorer | queries | valid evasion |
|---|---|---|
| replica | 16 | 12.5% (2/16) |
| real Snort | 16 | 12.5% (2/16) |

Identical. At 1 epoch the policy is near-random, so this is a weak comparison
that mainly confirms the plumbing, not the policy.

## How to state this in the paper

Call it **surrogate-biased optimization**, not surrogate unfaithfulness. A
pessimistic defender constrains the search without lying to it. The claim the data
supports is: *policy soundness is preserved by a one-sided pessimistic surrogate;
its cost is search inefficiency, measurable and quantified here.*

## Reproduce

```
.venv/bin/python3 controls/surrogate_sweep_14mech.py --n-flows 16
.venv/bin/python3 controls/surrogate_vs_real_snort.py --n-flows 8
```

Results: `snort_validation/reports/surrogate_sweep_14mech.json`,
`snort_validation/reports/surrogate_vs_real_snort.json`.
