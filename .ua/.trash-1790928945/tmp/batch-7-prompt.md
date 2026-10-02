Analyze these files and produce GraphNode and GraphEdge objects.

FIRST: Read the agent definition at `/root/.understand-anything-plugin/agents/file-analyzer.md` and follow its output protocol EXACTLY.

Project root: `/root/.hermes/c2-evasion-rl`
Project: `c2-evasion-rl` — RL red-team agent biến đổi gói tin C2 beacon thật để né Snort 2.9.20 (ET Open C2 ruleset), chấm điểm bằng binary Snort thật.
Languages: Python, Bash, Markdown, YAML
Batch: 7/8
Skill directory (for bundled scripts): `/root/.hermes/skills/understand-anything/understand`
Output: write to `/root/.hermes/c2-evasion-rl/.ua/intermediate/batch-7.json` (single-file mode) OR `batch-7-part-<k>.json` (split mode, per Step B of your output protocol).

Pre-resolved import data for this batch (use directly — do NOT re-resolve imports from source):
```json
{"snort_validation/surrogate_dataset.py": [], "snort_validation/test_snort_batch_service.py": [], "snort_validation/test_stratosphere_sweep.py": [], "snort_validation/test_surrogate_data.py": [], "snort_validation/train_real_snort_surrogate.py": [], "snort_validation/train_snort_surrogate.py": [], "snort_validation/validate_features_vs_snort.py": [], "snort_validation/validate_real_features_vs_snort.py": [], "snort_validation/validate_with_snort.py": [], "snort_validation/verify_snort_replica.py": [], "test_direction_1.py": [], "test_direction_2.py": [], "tests/_packets.py": [], "tests/test_alert_id_independence.py": [], "tests/test_beats_control.py": [], "tests/test_c2_semantics.py": [], "tests/test_corrupted_bookkeeping.py": [], "tests/test_direction_2_masking.py": [], "tests/test_endpoint_model.py": [], "tests/test_eval_cross_capture_determinism.py": [], "tests/test_fragment_ops.py": [], "tests/test_hidden_defender_env.py": [], "tests/test_mechanisms_ab.py": [], "tests/test_packet_features.py": [], "tests/test_packet_level_env.py": []}
```

Cross-batch neighbors with their exported symbols (confidence boost for cross-batch edges):
```json
{}
```

Files to analyze in this batch (every entry MUST be passed through to `batchFiles` with all four fields — `path`, `language`, `sizeLines`, `fileCategory`):
1. `snort_validation/surrogate_dataset.py` (142 lines, language: `python`, fileCategory: `code`)
2. `snort_validation/test_snort_batch_service.py` (131 lines, language: `python`, fileCategory: `code`)
3. `snort_validation/test_stratosphere_sweep.py` (219 lines, language: `python`, fileCategory: `code`)
4. `snort_validation/test_surrogate_data.py` (30 lines, language: `python`, fileCategory: `code`)
5. `snort_validation/train_real_snort_surrogate.py` (208 lines, language: `python`, fileCategory: `code`)
6. `snort_validation/train_snort_surrogate.py` (151 lines, language: `python`, fileCategory: `code`)
7. `snort_validation/validate_features_vs_snort.py` (329 lines, language: `python`, fileCategory: `code`)
8. `snort_validation/validate_real_features_vs_snort.py` (257 lines, language: `python`, fileCategory: `code`)
9. `snort_validation/validate_with_snort.py` (291 lines, language: `python`, fileCategory: `code`)
10. `snort_validation/verify_snort_replica.py` (173 lines, language: `python`, fileCategory: `code`)
11. `test_direction_1.py` (105 lines, language: `python`, fileCategory: `code`)
12. `test_direction_2.py` (112 lines, language: `python`, fileCategory: `code`)
13. `tests/_packets.py` (20 lines, language: `python`, fileCategory: `code`)
14. `tests/test_alert_id_independence.py` (64 lines, language: `python`, fileCategory: `code`)
15. `tests/test_beats_control.py` (179 lines, language: `python`, fileCategory: `code`)
16. `tests/test_c2_semantics.py` (54 lines, language: `python`, fileCategory: `code`)
17. `tests/test_corrupted_bookkeeping.py` (67 lines, language: `python`, fileCategory: `code`)
18. `tests/test_direction_2_masking.py` (107 lines, language: `python`, fileCategory: `code`)
19. `tests/test_endpoint_model.py` (91 lines, language: `python`, fileCategory: `code`)
20. `tests/test_eval_cross_capture_determinism.py` (119 lines, language: `python`, fileCategory: `code`)
21. `tests/test_fragment_ops.py` (142 lines, language: `python`, fileCategory: `code`)
22. `tests/test_hidden_defender_env.py` (176 lines, language: `python`, fileCategory: `code`)
23. `tests/test_mechanisms_ab.py` (94 lines, language: `python`, fileCategory: `code`)
24. `tests/test_packet_features.py` (111 lines, language: `python`, fileCategory: `code`)
25. `tests/test_packet_level_env.py` (72 lines, language: `python`, fileCategory: `code`)

**Additional context from main session:**

Project: `c2-evasion-rl` — RL agent for C2 traffic evasion against Snort IDS; current system is the 14-mechanism HiddenDefenderEnv trained with MaskablePPO, scored by the real Snort binary. Key subsystems: `ai_agent/` (RL envs + training), `snort_validation/` (real Snort integration, corpus building, evaluation harnesses), `controls/` (correctness controls), `tests/`.

> **Language directive**: Generate all textual content (summaries, descriptions, tags, titles, languageNotes, languageLesson) in **Vietnamese (tiếng Việt)**. Maintain technical accuracy while using natural, native-level phrasing. Keep technical terms in English when no standard translation exists (e.g., "middleware", "hook", "surrogate", "batch").
