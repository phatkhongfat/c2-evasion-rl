Analyze these files and produce GraphNode and GraphEdge objects.

FIRST: Read the agent definition at `/root/.understand-anything-plugin/agents/file-analyzer.md` and follow its output protocol EXACTLY.

Project root: `/root/.hermes/c2-evasion-rl`
Project: `c2-evasion-rl` — RL red-team agent biến đổi gói tin C2 beacon thật để né Snort 2.9.20 (ET Open C2 ruleset), chấm điểm bằng binary Snort thật.
Languages: Python, Bash, Markdown, YAML
Batch: 5/8
Skill directory (for bundled scripts): `/root/.hermes/skills/understand-anything/understand`
Output: write to `/root/.hermes/c2-evasion-rl/.ua/intermediate/batch-5.json` (single-file mode) OR `batch-5-part-<k>.json` (split mode, per Step B of your output protocol).

Pre-resolved import data for this batch (use directly — do NOT re-resolve imports from source):
```json
{"snort_validation/augment_corpus_no_gym.py": [], "snort_validation/augment_corpus_with_framing.py": [], "snort_validation/baseline_hidden_defender.py": [], "snort_validation/batch_integrity.py": [], "snort_validation/build_et_open_c2_ruleset.py": [], "snort_validation/build_hidden_defender_corpus.py": [], "snort_validation/build_mcfp_snort_dataset.py": [], "snort_validation/build_real_snort_dataset.py": [], "snort_validation/c2_semantics.py": [], "snort_validation/capture_pool_sizes.py": [], "snort_validation/compare_snort_direct.py": [], "snort_validation/control_gate.py": [], "snort_validation/corpus_framing_report.py": [], "snort_validation/detection_rate_by_framing.py": [], "snort_validation/diagnose_generalization.py": [], "snort_validation/endpoint_model.py": [], "snort_validation/enhanced_snort_replica.py": [], "snort_validation/eval_all_real_snort.py": [], "snort_validation/eval_policy_horizon.py": [], "snort_validation/eval_surrogate_cross_validate.py": [], "snort_validation/evasion_fidelity_test.py": [], "snort_validation/extract_ctu13_features.py": [], "snort_validation/extract_ctu13_real_features.py": [], "snort_validation/final_aggregate_scale_up.py": [], "snort_validation/flow_to_pcap.py": []}
```

Cross-batch neighbors with their exported symbols (confidence boost for cross-batch edges):
```json
{}
```

Files to analyze in this batch (every entry MUST be passed through to `batchFiles` with all four fields — `path`, `language`, `sizeLines`, `fileCategory`):
1. `snort_validation/augment_corpus_no_gym.py` (42 lines, language: `python`, fileCategory: `code`)
2. `snort_validation/augment_corpus_with_framing.py` (36 lines, language: `python`, fileCategory: `code`)
3. `snort_validation/baseline_hidden_defender.py` (169 lines, language: `python`, fileCategory: `code`)
4. `snort_validation/batch_integrity.py` (80 lines, language: `python`, fileCategory: `code`)
5. `snort_validation/build_et_open_c2_ruleset.py` (225 lines, language: `python`, fileCategory: `code`)
6. `snort_validation/build_hidden_defender_corpus.py` (154 lines, language: `python`, fileCategory: `code`)
7. `snort_validation/build_mcfp_snort_dataset.py` (204 lines, language: `python`, fileCategory: `code`)
8. `snort_validation/build_real_snort_dataset.py` (94 lines, language: `python`, fileCategory: `code`)
9. `snort_validation/c2_semantics.py` (121 lines, language: `python`, fileCategory: `code`)
10. `snort_validation/capture_pool_sizes.py` (67 lines, language: `python`, fileCategory: `code`)
11. `snort_validation/compare_snort_direct.py` (84 lines, language: `python`, fileCategory: `code`)
12. `snort_validation/control_gate.py` (59 lines, language: `python`, fileCategory: `code`)
13. `snort_validation/corpus_framing_report.py` (70 lines, language: `python`, fileCategory: `code`)
14. `snort_validation/detection_rate_by_framing.py` (59 lines, language: `python`, fileCategory: `code`)
15. `snort_validation/diagnose_generalization.py` (277 lines, language: `python`, fileCategory: `code`)
16. `snort_validation/endpoint_model.py` (127 lines, language: `python`, fileCategory: `code`)
17. `snort_validation/enhanced_snort_replica.py` (121 lines, language: `python`, fileCategory: `code`)
18. `snort_validation/eval_all_real_snort.py` (239 lines, language: `python`, fileCategory: `code`)
19. `snort_validation/eval_policy_horizon.py` (184 lines, language: `python`, fileCategory: `code`)
20. `snort_validation/eval_surrogate_cross_validate.py` (208 lines, language: `python`, fileCategory: `code`)
21. `snort_validation/evasion_fidelity_test.py` (69 lines, language: `python`, fileCategory: `code`)
22. `snort_validation/extract_ctu13_features.py` (258 lines, language: `python`, fileCategory: `code`)
23. `snort_validation/extract_ctu13_real_features.py` (413 lines, language: `python`, fileCategory: `code`)
24. `snort_validation/final_aggregate_scale_up.py` (47 lines, language: `python`, fileCategory: `code`)
25. `snort_validation/flow_to_pcap.py` (264 lines, language: `python`, fileCategory: `code`)

**Additional context from main session:**

Project: `c2-evasion-rl` — RL agent for C2 traffic evasion against Snort IDS; current system is the 14-mechanism HiddenDefenderEnv trained with MaskablePPO, scored by the real Snort binary. Key subsystems: `ai_agent/` (RL envs + training), `snort_validation/` (real Snort integration, corpus building, evaluation harnesses), `controls/` (correctness controls), `tests/`.

> **Language directive**: Generate all textual content (summaries, descriptions, tags, titles, languageNotes, languageLesson) in **Vietnamese (tiếng Việt)**. Maintain technical accuracy while using natural, native-level phrasing. Keep technical terms in English when no standard translation exists (e.g., "middleware", "hook", "surrogate", "batch").
