Analyze these files and produce GraphNode and GraphEdge objects.

FIRST: Read the agent definition at `/root/.understand-anything-plugin/agents/file-analyzer.md` and follow its output protocol EXACTLY.

Project root: `/root/.hermes/c2-evasion-rl`
Project: `c2-evasion-rl` — RL red-team agent biến đổi gói tin C2 beacon thật để né Snort 2.9.20 (ET Open C2 ruleset), chấm điểm bằng binary Snort thật.
Languages: Python, Bash, Markdown, YAML
Batch: 6/8
Skill directory (for bundled scripts): `/root/.hermes/skills/understand-anything/understand`
Output: write to `/root/.hermes/c2-evasion-rl/.ua/intermediate/batch-6.json` (single-file mode) OR `batch-6-part-<k>.json` (split mode, per Step B of your output protocol).

Pre-resolved import data for this batch (use directly — do NOT re-resolve imports from source):
```json
{"snort_validation/frag3_policy_comparison.py": [], "snort_validation/fragment_ops.py": [], "snort_validation/fragment_validity_test.py": [], "snort_validation/frontier_exact.py": [], "snort_validation/harness_variance.py": [], "snort_validation/joint_outcomes.py": [], "snort_validation/label_feasibility.py": [], "snort_validation/label_real_flows_with_snort.py": [], "snort_validation/offset_sweep_test.py": [], "snort_validation/parse_http_eval.py": [], "snort_validation/prepare_enhanced_surrogate_data.py": [], "snort_validation/probe_overlap_evasion.py": [], "snort_validation/real_rules_replica.py": [], "snort_validation/register_stratosphere_captures.py": [], "snort_validation/rules/botnet-aggressive.rules": [], "snort_validation/rules/botnet-behavior.rules": [], "snort_validation/rules/classification.config": [], "snort_validation/rules/reference.config": [], "snort_validation/rules/snort.conf": [], "snort_validation/run_evaluation.py": [], "snort_validation/semantics_strict_test.py": [], "snort_validation/smoke_test.py": [], "snort_validation/snort_batch_service.py": [], "snort_validation/snort_query_service.py": [], "snort_validation/snort_resident_service.py": []}
```

Cross-batch neighbors with their exported symbols (confidence boost for cross-batch edges):
```json
{}
```

Files to analyze in this batch (every entry MUST be passed through to `batchFiles` with all four fields — `path`, `language`, `sizeLines`, `fileCategory`):
1. `snort_validation/frag3_policy_comparison.py` (109 lines, language: `python`, fileCategory: `code`)
2. `snort_validation/fragment_ops.py` (146 lines, language: `python`, fileCategory: `code`)
3. `snort_validation/fragment_validity_test.py` (112 lines, language: `python`, fileCategory: `code`)
4. `snort_validation/frontier_exact.py` (166 lines, language: `python`, fileCategory: `code`)
5. `snort_validation/harness_variance.py` (59 lines, language: `python`, fileCategory: `code`)
6. `snort_validation/joint_outcomes.py` (28 lines, language: `python`, fileCategory: `code`)
7. `snort_validation/label_feasibility.py` (165 lines, language: `python`, fileCategory: `code`)
8. `snort_validation/label_real_flows_with_snort.py` (244 lines, language: `python`, fileCategory: `code`)
9. `snort_validation/offset_sweep_test.py` (95 lines, language: `python`, fileCategory: `code`)
10. `snort_validation/parse_http_eval.py` (62 lines, language: `python`, fileCategory: `code`)
11. `snort_validation/prepare_enhanced_surrogate_data.py` (141 lines, language: `python`, fileCategory: `code`)
12. `snort_validation/probe_overlap_evasion.py` (166 lines, language: `python`, fileCategory: `code`)
13. `snort_validation/real_rules_replica.py` (388 lines, language: `python`, fileCategory: `code`)
14. `snort_validation/register_stratosphere_captures.py` (102 lines, language: `python`, fileCategory: `code`)
15. `snort_validation/rules/botnet-aggressive.rules` (54 lines, language: `rules`, fileCategory: `code`)
16. `snort_validation/rules/botnet-behavior.rules` (61 lines, language: `rules`, fileCategory: `code`)
17. `snort_validation/rules/classification.config` (70 lines, language: `config`, fileCategory: `code`)
18. `snort_validation/rules/reference.config` (16 lines, language: `config`, fileCategory: `code`)
19. `snort_validation/rules/snort.conf` (37 lines, language: `conf`, fileCategory: `code`)
20. `snort_validation/run_evaluation.py` (257 lines, language: `python`, fileCategory: `code`)
21. `snort_validation/semantics_strict_test.py` (120 lines, language: `python`, fileCategory: `code`)
22. `snort_validation/smoke_test.py` (20 lines, language: `python`, fileCategory: `code`)
23. `snort_validation/snort_batch_service.py` (366 lines, language: `python`, fileCategory: `code`)
24. `snort_validation/snort_query_service.py` (257 lines, language: `python`, fileCategory: `code`)
25. `snort_validation/snort_resident_service.py` (483 lines, language: `python`, fileCategory: `code`)

**Additional context from main session:**

Project: `c2-evasion-rl` — RL agent for C2 traffic evasion against Snort IDS; current system is the 14-mechanism HiddenDefenderEnv trained with MaskablePPO, scored by the real Snort binary. Key subsystems: `ai_agent/` (RL envs + training), `snort_validation/` (real Snort integration, corpus building, evaluation harnesses), `controls/` (correctness controls), `tests/`.

> **Language directive**: Generate all textual content (summaries, descriptions, tags, titles, languageNotes, languageLesson) in **Vietnamese (tiếng Việt)**. Maintain technical accuracy while using natural, native-level phrasing. Keep technical terms in English when no standard translation exists (e.g., "middleware", "hook", "surrogate", "batch").
