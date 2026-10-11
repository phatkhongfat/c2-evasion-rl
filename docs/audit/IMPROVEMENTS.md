# Prioritized improvements

## Must resolve before publishing current strong claims
- F01: README.md and results prose — label offline static validity accurately; do not claim working endpoint based solely on byte matching. Acceptance: all claims map to measured scope.
- F02: snort_validation/reports/ and report-producing entrypoints — preserve historical runs, specify corpus/config/code/checkpoint hashes and metric definitions. Review current overwritten training report rather than editing verifier assertions until green.
- F06: snort_validation/eval_pipeline.py measurement contract — propose a separate benign-control verification plan with processing-health and UNKNOWN outcomes. No packet-evasion optimization.

## Should improve before submission
- F03/F07: environment.yml, README.md, Makefile — pick one approved Python environment, install through that interpreter, test clean install elsewhere; don't repair the current mixed environment in place without backup/approval.
- F04: corpus_config.py and tests/test_corpus_split.py — document authoritative builder and exact split provenance; verify IDs, capture grouping and duplicate checks, not only split sizes. Preserve old results and report their within-capture limitation.
- F05: train_hidden_defender_ppo.py/docs — accurately describe contextual-bandit formulation. Require matched baseline protocol before any statement that PPO is superior; a negative result is acceptable.
- F08: tests/ — separate synthetic/static checks from corpus/engine tests, independent oracle tests and runtime tests. New code changes use RED→GREEN on benign fixtures, then review/regression/explicit-path commit.

## Optional after correctness
Consolidate duplicated dispatch only after a parity contract; remove hardcoded paths; replace source-substring CLI tests with behavior tests where safe; improve docs index and archive labels. No automatic deletion of old environments, odd filenames, reports or logs.

## Execution order and effort
Evidence/docs freeze: hours. Environment recreation: half-day subject to package access. Independent measurement validation: separate lab plan, days. Data/baseline protocol: day+ and dataset-dependent. Refactoring last; no performance percentage or success probability is invented.

## Gates
Do not launch further training until provenance and measurement scope are fixed. Do not claim live-functionality until independent endpoint/deadline evidence exists. No broad rewrite or new action space is necessary for the audit findings themselves.
