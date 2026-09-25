# Documentation Audit (Phase 1)

Inventory and categorization performed before the docs reorganization.
See [`../README.md`](../README.md) for the resulting structure.

```
DOCUMENTATION AUDIT — C2-Evasion RL
Generated: 2026-09-25  (plan 2026-09-25_220000, Tasks 1.1-1.3)
Repo: /root/.hermes/c2-evasion-rl
Branch: packet-level-rl
Root .md files inventoried: 24

=== CATEGORY A: Final/Latest Reports (RELOCATE to sections) ===
FINAL_EXECUTION_REPORT.md  -> docs/03-experiments/results-final.md        (latest 11 real Snort measurements)
FINAL_CORRECTED_REPORT.md  -> docs/04-challenges/root-cause-analysis.md   (root-cause analysis, corrected numbers)

=== CATEGORY B: Earlier Reports (ARCHIVE -> docs/06-archive/old-reports/) ===
COMPREHENSIVE_FINAL_REPORT.md
FINAL_REPORT.md
FINAL_STRATOSPHERE_REPORT.md
SNORT_VALIDATION_RESULTS.md
FINAL_VALIDATION_REPORT.md
EXECUTION_SUMMARY.md

=== CATEGORY C: Task/Investigation Notes (ARCHIVE -> docs/06-archive/investigation-notes/) ===
TASK_5_6_COMPLETION_REPORT.md
TASK_5_DECISION_GATE.md
TASK6_DECISION_GATE.md
TASK6_FINAL_STATE.md
INVESTIGATION_BASELINE_PARADOX.md
PACKET_LEVEL_RL_COMPLETION.md
SCALE_UP_VALIDATION.md
PIPELINE_SUMMARY.md
DELIVERY.md
FINAL_CHECKLIST.md
FINAL_TASK6_REPORT.md
STATUS.md
STRATOSPHERE_SWEEP_EXECUTION.md

=== CATEGORY D: Live Root Documents (KEEP at repo root, plan Task 2.3) ===
README.md          (rewritten in Phase 3)
README.vi.md       (rewritten in Phase 3)
CHANGELOG.md       (living changelog; plan tasks 1.1-2.5 never relocate it)

=== EXISTING docs/ CONTENTS (kept in place; Phase 2 does not relocate) ===
docs/CHANGELOG_SNORT_INTEGRATION.md, docs/DATASET_AND_RULESET_SWITCH.md,
docs/REAL_SNORT_IN_THE_LOOP.md, docs/SNORT_DECISION_BOUNDARIES.md,
docs/SNORT_DIRECT_TASK5_CORRECTED.md, docs/evasion_ceiling_analysis.md,
docs/packet_level_rl.md, docs/packet_level_rl_results.md,
docs/packet_level_subset_analysis.md, docs/tcp10_trained_results.md,
docs/pipeline.mmd, docs/pipeline.png, docs/pipeline.svg

=== LINK-REFERENCE NOTES (checked before moving) ===
- docs/pipeline.*        referenced by README.md / README.vi.md -> keep in docs/
- docs/packet_level_rl*.md referenced by README.md -> keep in docs/
- docs/SNORT_DIRECT_TASK5_CORRECTED.md referenced by FINAL_REPORT.md, SNORT_VALIDATION_RESULTS.md, CHANGELOG.md, README.md
- docs/SNORT_DECISION_BOUNDARIES.md    referenced by INVESTIGATION_BASELINE_PARADOX.md
- Root .md files are not cross-referenced by code; moves are safe.

SUMMARY: 21 root .md relocated (6 old-reports, 13 investigation-notes, 2 key reports to sections).
         3 root .md retained (README.md, README.vi.md per plan; CHANGELOG.md as living doc).
```
