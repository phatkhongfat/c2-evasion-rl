Analyze these files and produce GraphNode and GraphEdge objects.

FIRST: Read the agent definition at `/root/.understand-anything-plugin/agents/file-analyzer.md` and follow its output protocol EXACTLY.

Project root: `/root/.hermes/c2-evasion-rl`
Project: `c2-evasion-rl` — RL red-team agent biến đổi gói tin C2 beacon thật để né Snort 2.9.20 (ET Open C2 ruleset), chấm điểm bằng binary Snort thật.
Languages: Python, Bash, Markdown, YAML
Batch: 4/8
Skill directory (for bundled scripts): `/root/.hermes/skills/understand-anything/understand`
Output: write to `/root/.hermes/c2-evasion-rl/.ua/intermediate/batch-4.json` (single-file mode) OR `batch-4-part-<k>.json` (split mode, per Step B of your output protocol).

Pre-resolved import data for this batch (use directly — do NOT re-resolve imports from source):
```json
{"ai_agent/train_real_snort_agent.py": [], "ai_agent/train_replica_agent.py": [], "ai_agent/verify_against_real_snort.py": [], "ai_agent/verify_real_env.py": [], "blue_team/train_ids.ipynb": [], "blue_team/train_surrogate.ipynb": [], "blue_team/train_surrogate_xgboost.ipynb": [], "controls/control_noop_real_snort.py": [], "controls/surrogate_sweep_14mech.py": [], "controls/surrogate_vs_real_snort.py": [], "controls/verify_report_claims.py": [], "models/.gitkeep": [], "models/xgboost_judge_ctu13_10_directional.joblib": [], "models/xgboost_judge_ctu13_10_directional_features.json": [], "models/xgboost_judge_directional_10feat.joblib": [], "models/xgboost_judge_directional_10feat_features.json": [], "red_team/mock_client.py": [], "red_team/mock_server.py": [], "scripts/measure_action_impact.py": [], "scripts/test_enhanced_replica.py": [], "scripts/trace_action_to_reward.py": [], "setup_check.py": [], "snort_validation/aggregate_results.py": [], "snort_validation/aggregate_scale_up.py": [], "snort_validation/aggressive_snort_replica.py": []}
```

Cross-batch neighbors with their exported symbols (confidence boost for cross-batch edges):
```json
{}
```

Files to analyze in this batch (every entry MUST be passed through to `batchFiles` with all four fields — `path`, `language`, `sizeLines`, `fileCategory`):
1. `ai_agent/train_real_snort_agent.py` (134 lines, language: `python`, fileCategory: `code`)
2. `ai_agent/train_replica_agent.py` (307 lines, language: `python`, fileCategory: `code`)
3. `ai_agent/verify_against_real_snort.py` (75 lines, language: `python`, fileCategory: `code`)
4. `ai_agent/verify_real_env.py` (65 lines, language: `python`, fileCategory: `code`)
5. `blue_team/train_ids.ipynb` (437 lines, language: `ipynb`, fileCategory: `code`)
6. `blue_team/train_surrogate.ipynb` (287 lines, language: `ipynb`, fileCategory: `code`)
7. `blue_team/train_surrogate_xgboost.ipynb` (273 lines, language: `ipynb`, fileCategory: `code`)
8. `controls/control_noop_real_snort.py` (61 lines, language: `python`, fileCategory: `code`)
9. `controls/surrogate_sweep_14mech.py` (146 lines, language: `python`, fileCategory: `code`)
10. `controls/surrogate_vs_real_snort.py` (103 lines, language: `python`, fileCategory: `code`)
11. `controls/verify_report_claims.py` (117 lines, language: `python`, fileCategory: `code`)
12. `models/.gitkeep` (0 lines, language: `unknown`, fileCategory: `code`)
13. `models/xgboost_judge_ctu13_10_directional.joblib` (314 lines, language: `joblib`, fileCategory: `code`)
14. `models/xgboost_judge_ctu13_10_directional_features.json` (18 lines, language: `json`, fileCategory: `config`)
15. `models/xgboost_judge_directional_10feat.joblib` (349 lines, language: `joblib`, fileCategory: `code`)
16. `models/xgboost_judge_directional_10feat_features.json` (13 lines, language: `json`, fileCategory: `config`)
17. `red_team/mock_client.py` (12 lines, language: `python`, fileCategory: `code`)
18. `red_team/mock_server.py` (12 lines, language: `python`, fileCategory: `code`)
19. `scripts/measure_action_impact.py` (74 lines, language: `python`, fileCategory: `code`)
20. `scripts/test_enhanced_replica.py` (32 lines, language: `python`, fileCategory: `code`)
21. `scripts/trace_action_to_reward.py` (152 lines, language: `python`, fileCategory: `code`)
22. `setup_check.py` (118 lines, language: `python`, fileCategory: `code`)
23. `snort_validation/aggregate_results.py` (196 lines, language: `python`, fileCategory: `code`)
24. `snort_validation/aggregate_scale_up.py` (53 lines, language: `python`, fileCategory: `code`)
25. `snort_validation/aggressive_snort_replica.py` (246 lines, language: `python`, fileCategory: `code`)

**Additional context from main session:**

Project: `c2-evasion-rl` — RL agent for C2 traffic evasion against Snort IDS; current system is the 14-mechanism HiddenDefenderEnv trained with MaskablePPO, scored by the real Snort binary. Key subsystems: `ai_agent/` (RL envs + training), `snort_validation/` (real Snort integration, corpus building, evaluation harnesses), `controls/` (correctness controls), `tests/`.

> **Language directive**: Generate all textual content (summaries, descriptions, tags, titles, languageNotes, languageLesson) in **Vietnamese (tiếng Việt)**. Maintain technical accuracy while using natural, native-level phrasing. Keep technical terms in English when no standard translation exists (e.g., "middleware", "hook", "surrogate", "batch").
