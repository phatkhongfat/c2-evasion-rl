# Pre-research readiness audit — conclusion

## Verdict
- **Software: CONDITIONAL** — existing implementation and tests form a useful prototype, but install/execution environments disagree and clean reproduction is unverified.
- **Measurement: CONDITIONAL for offline diagnostics; NO-GO for live-functionality claims** — real Snort report counts exist, but byte equality is not independent endpoint completion and final-artifact health needs evidence.
- **Research: NO-GO for the current strong headline** — generalization, exact run provenance and ML benefit are insufficiently established. This does not invalidate all existing code or require a rewrite.

## What is already useful
Real-Snort integration, a nonzero-exit failure path, shared byte oracle, negative-control report and protocol-focused tests. Recomputed report: 40 distinct flow IDs, no duplicate cells; noop valid 0/40 versus split_slow 40/40 under the existing offline bar. These counts are not a new live-network experiment or PPO evaluation.

## Verified during this audit
- 5 synthetic semantics tests passed in 0.02s, exit 0. Full suite NOT rerun.
- Default corpus metadata: 1153 train / 40 test, zero exact flow-ID overlap, but shared captures across splits.
- Three historical policy reports choose one fixed action on all test flows; no causal learned-policy advantage follows.
- pip shebang points at Python 3.12, runtime is Python 3.11.16, sb3-contrib live 2.2.1 vs declared 2.9.0.
- setup_check.py absent; current training report differs from README training run.

## Rubric
Runtime/reproducibility: PARTIAL. Measurement correctness: PARTIAL with endpoint/final-artifact gaps. Data quality/generalization: PARTIAL. ML formulation/evidence: PARTIAL. Tests: PARTIAL; independent endpoint validation UNKNOWN. Maintainability: PARTIAL. Research claim traceability: FAIL for the strong live/generalization claim, not for all historical counts.

## Improvements, in order
1. F01/F02: narrow unsupported claims and preserve evidence with explicit provenance.
2. F06: verify detector health and validity against independent benign controls.
3. F03/F07: make interpreter/setup/report path coherent and reproducible.
4. F04/F05: establish split scope and fair baseline comparison before additional ML training.
5. F08: independent tests, then focused DRY/doc cleanup.

## Limits and completion scope
Static/evidence audit completed; clean install, full-suite execution, checkpoint load, live endpoint and new detector experiments NOT performed. These remain UNKNOWN, not assumed failures. Some secondary reviewer findings (exact split regeneration discrepancy, model inventory) are retained as follow-up rather than promoted to independently confirmed facts.
No source fixes, dependency changes, traffic generation, training, deletions, commits or pushes. Audit documentation only was added.
See findings.md for evidence/acceptance and IMPROVEMENTS.md for actionable order.
