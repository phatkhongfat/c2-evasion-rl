# Documentation Index

The repo keeps **one version** of the system: the 14-mechanism `HiddenDefenderEnv`
trained with MaskablePPO, scored by real Snort 2.9.20 (ET Open C2). Retired
generations (flow-level surrogate, packet-level, directional, snort-aware, bandit
sweeps) were deleted in the one-version cleanup — everything remains recoverable
from git history (see commit `2dc23af`).

## Read in this order

| # | Document | What it gives you |
|---|----------|-------------------|
| 1 | [`/README.md`](../README.md) · [`/README.vi.md`](../README.vi.md) | Quick start, layout, headline results, honest caveats |
| 2 | [`RESULTS_PRESENTATION.md`](RESULTS_PRESENTATION.md) | **How every headline number is produced and verified.** The authoritative results doc — `controls/verify_report_claims.py` re-derives all 53 claims from it |
| 3 | [`hidden_defender_results.md`](hidden_defender_results.md) | Current-system measurement detail: PPO vs greedy vs baselines, mechanism matrix, why the task saturates, the retracted 100% artifact |
| 4 | [`surrogate_vs_reality_audit.md`](surrogate_vs_reality_audit.md) | 224 real-Snort-call audit of where the fast surrogate agrees/diverges |
| 5 | [`REAL_SNORT_IN_THE_LOOP.md`](REAL_SNORT_IN_THE_LOOP.md) | Real-Snort training loop, resident-service findings (12/12 verified, bandit integration caveat) |

## Supporting references

| Document | Content |
|----------|---------|
| [`dataset-sources.md`](dataset-sources.md) | Where CTU-13 / Stratosphere captures and ET Open rules come from |
| [`DATASET_AND_RULESET_SWITCH.md`](DATASET_AND_RULESET_SWITCH.md) | Why the project moved to ET Open C2 + raw pcaps |
| [`CHANGELOG_SNORT_INTEGRATION.md`](CHANGELOG_SNORT_INTEGRATION.md) | Chronological log of the Snort integration work |
| [`SNORT_DECISION_BOUNDARIES.md`](SNORT_DECISION_BOUNDARIES.md) | What the ET Open C2 ruleset actually keys on (depth, content anchors) |
| [`http_only_eval_results.md`](http_only_eval_results.md) | Per-mechanism results on the HTTP-only test slice (feeds RESULTS_PRESENTATION §4) |
| [`mechanisms_ab_results.md`](mechanisms_ab_results.md) | Mechanism A (http_header_pad) / B (length_wrapper) design + measurements |
| [`academic_mechanisms_mapping.md`](academic_mechanisms_mapping.md) | Mapping of academic evasion techniques (NOP-sled analogues, fragmentation, morphing) onto the C2 problem |

## Working documents (may be acted on or deleted later)

| Document | Content |
|----------|---------|
| [`advisor_email_draft.md`](advisor_email_draft.md) | Draft email: surrogate→real-Snort transition, 9 issues, 5 questions |
| [`questions_for_advisor.md`](questions_for_advisor.md) | Open questions for the thesis advisor |
| [`surrogate_to_real_snort_issues.md`](surrogate_to_real_snort_issues.md) | Issue log from the transition (feeds the advisor email) |
| [`three_directions_implementation_plan.md`](three_directions_implementation_plan.md) | Plan for cost-penalty / protocol-masking / heterogeneous-defender directions — Directions 1–2 are implemented and tested; Direction 3 (heterogeneous defender) is the open research item |

## Thesis

[`thesis/`](thesis/) — LaTeX theses (EN + VI) with Makefile. **Known stale:** the
`.tex` files still describe the retired bandit/Stratosphere generation (no mention
of the 16/16 headline, `split8`, `http_header_pad`, or MaskablePPO). Rewriting them
against `RESULTS_PRESENTATION.md` + `hidden_defender_results.md` is an open task —
do not treat the current PDFs as accurate.

## Repo-root docs

[`/CHANGELOG.md`](../CHANGELOG.md) · [`/PROGRESS_REPORT.md`](../PROGRESS_REPORT.md) ·
[`/WINDOWS_COMPAT.md`](../WINDOWS_COMPAT.md)
