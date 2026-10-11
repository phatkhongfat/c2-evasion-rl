# Findings register
Priority relates to scientific use, not cosmetic severity.

## F01 — P0 — confirmed claim gap
Evidence: eval_pipeline.py:436–451; c2_semantics.py:329–404; README.md:5–10.
Static bytes/reassembly is used for validity before final serialization; no endpoint/deadline oracle in score. Impact: working-connection claim exceeds evidence. Fix direction: scope claims to offline predicate now; separately validate benign endpoint and final-artifact invariants. Acceptance: every live-functionality claim has independent response/deadline evidence, or is removed. Effort: documentation hours; lab validation days, separately approved.

## F02 — P0 — confirmed provenance gap
Evidence: ceiling_v3_splitslow_fixed.json top-level schema; modified ppo_hidden_defender.json; dirty working tree.
Historical and current run outputs lack sufficient immutable provenance to attribute all claims to exact code/config/data. Acceptance: preserved run-specific artifacts, hashes and distinction between cumulative and final metrics; no overwriting old result to pass verifier. Effort: half-day to day; missing historical metadata may remain unknown.

## F03 — P1 — confirmed dependency/install mismatch
Evidence: live Python metadata, .venv/bin/pip first line, environment.yml:49.
Execution uses Python 3.11 + contrib 2.2.1; pip points at Python 3.12, declared contrib is 2.9.0. Acceptance: one approved interpreter/install path plus clean isolated install and benign smoke test. Do not manually patch shebang or delete environments before selecting/rebuilding approved environment. Effort: half-day, dependency availability unknown.

## F04 — P1 — confirmed generalization limitation
Evidence: hidden_defender_corpus.json train/test capture lists; recomputation ID overlap 0.
No capture-disjoint test demonstrated for the default corpus. Acceptance: dataset manifest, group split and exact identity regression; old test labeled within-capture/development. Effort: day+, data-dependent.

## F05 — P1 — confirmed formulation / baseline limitation
Evidence: train_hidden_defender_ppo.py:39–40,159–161; historical both_v2 policy reports.
One-step selection with gamma=0 and fixed action across test flows does not establish sequential-RL benefit. Acceptance: correct bandit description and fair fixed/random/bandit comparisons with equal scope/budget before claiming learned advantage. Effort: protocol hours; experiments separately approved. No need to force action diversity.

## F06 — P1 — unknown detector processing health
Evidence: eval_pipeline.py:354–401 and score schema.
Nonzero exit raises (good); packet-processing/reassembly health not part of persisted verdict. Absence of alert alone cannot distinguish every failure mode. Acceptance: benign positive/negative controls and explicit UNKNOWN for insufficient evidence; do not classify every missing alert file as failure. Effort: audit hours, instrumentation separate plan.

## F07 — P1/P2 — confirmed setup/docs drift
Evidence: setup_check.py absent despite environment.yml:5; hardcoded root train_hidden_defender_ppo.py:26; reviewer Makefile/docs analysis.
Acceptance: one verified setup path, no nonexistent commands, run-scoped documentation, portable root derivation where needed. Effort: hours; no broad cleanup or deletion authorized.

## F08 — P2 — confirmed test scope limitation
Evidence: tests.md, reviewed wire-deliverability and DNS tests.
In-memory tests share implementation helpers and are not independent network validation. Acceptance: test matrix distinguishes static invariants, serialized artifacts, endpoint behavior and historical corpus tests. Effort: hours for matrix; targeted benign tests planned later.
