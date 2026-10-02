Analyze these files and produce GraphNode and GraphEdge objects.

FIRST: Read the agent definition at `/root/.understand-anything-plugin/agents/file-analyzer.md` and follow its output protocol EXACTLY.

Project root: `/root/.hermes/c2-evasion-rl`
Project: `c2-evasion-rl` — RL red-team agent biến đổi gói tin C2 beacon thật để né Snort 2.9.20 (ET Open C2 ruleset), chấm điểm bằng binary Snort thật.
Languages: Python, Bash, Markdown, YAML
Batch: 3/8
Skill directory (for bundled scripts): `/root/.hermes/skills/understand-anything/understand`
Output: write to `/root/.hermes/c2-evasion-rl/.ua/intermediate/batch-3.json` (single-file mode) OR `batch-3-part-<k>.json` (split mode, per Step B of your output protocol).

Pre-resolved import data for this batch (use directly — do NOT re-resolve imports from source):
```json
{"ai_agent/ablate_actions.py": [], "ai_agent/c2_evasion_env.py": [], "ai_agent/callback_metric_proof.py": [], "ai_agent/config.py": [], "ai_agent/enhanced_packet_level_env.py": [], "ai_agent/eval_cross_capture.py": [], "ai_agent/eval_enhanced_agent.py": [], "ai_agent/eval_masked_ppo_test.py": [], "ai_agent/eval_packet_level_agent.py": [], "ai_agent/eval_real_snort_agent.py": [], "ai_agent/evaluate.py": [], "ai_agent/evasion_metrics_callback.py": [], "ai_agent/flow_features.py": [], "ai_agent/hidden_defender_env.py": [], "ai_agent/packet_level_env.py": [], "ai_agent/packet_modifier.py": [], "ai_agent/pool_loader.py": [], "ai_agent/real_packet_env.py": [], "ai_agent/snort_bandit.py": [], "ai_agent/train_agent.py": [], "ai_agent/train_enhanced.py": [], "ai_agent/train_enhanced_packet_agent.py": [], "ai_agent/train_hidden_defender_ppo.py": [], "ai_agent/train_packet_level_agent.py": [], "ai_agent/train_packet_level_tcp10.py": []}
```

Cross-batch neighbors with their exported symbols (confidence boost for cross-batch edges):
```json
{}
```

Files to analyze in this batch (every entry MUST be passed through to `batchFiles` with all four fields — `path`, `language`, `sizeLines`, `fileCategory`):
1. `ai_agent/ablate_actions.py` (108 lines, language: `python`, fileCategory: `code`)
2. `ai_agent/c2_evasion_env.py` (362 lines, language: `python`, fileCategory: `code`)
3. `ai_agent/callback_metric_proof.py` (87 lines, language: `python`, fileCategory: `code`)
4. `ai_agent/config.py` (51 lines, language: `python`, fileCategory: `code`)
5. `ai_agent/enhanced_packet_level_env.py` (163 lines, language: `python`, fileCategory: `code`)
6. `ai_agent/eval_cross_capture.py` (141 lines, language: `python`, fileCategory: `code`)
7. `ai_agent/eval_enhanced_agent.py` (110 lines, language: `python`, fileCategory: `code`)
8. `ai_agent/eval_masked_ppo_test.py` (88 lines, language: `python`, fileCategory: `code`)
9. `ai_agent/eval_packet_level_agent.py` (119 lines, language: `python`, fileCategory: `code`)
10. `ai_agent/eval_real_snort_agent.py` (106 lines, language: `python`, fileCategory: `code`)
11. `ai_agent/evaluate.py` (89 lines, language: `python`, fileCategory: `code`)
12. `ai_agent/evasion_metrics_callback.py` (66 lines, language: `python`, fileCategory: `code`)
13. `ai_agent/flow_features.py` (201 lines, language: `python`, fileCategory: `code`)
14. `ai_agent/hidden_defender_env.py` (417 lines, language: `python`, fileCategory: `code`)
15. `ai_agent/packet_level_env.py` (195 lines, language: `python`, fileCategory: `code`)
16. `ai_agent/packet_modifier.py` (85 lines, language: `python`, fileCategory: `code`)
17. `ai_agent/pool_loader.py` (83 lines, language: `python`, fileCategory: `code`)
18. `ai_agent/real_packet_env.py` (584 lines, language: `python`, fileCategory: `code`)
19. `ai_agent/snort_bandit.py` (587 lines, language: `python`, fileCategory: `code`)
20. `ai_agent/train_agent.py` (122 lines, language: `python`, fileCategory: `code`)
21. `ai_agent/train_enhanced.py` (110 lines, language: `python`, fileCategory: `code`)
22. `ai_agent/train_enhanced_packet_agent.py` (97 lines, language: `python`, fileCategory: `code`)
23. `ai_agent/train_hidden_defender_ppo.py` (166 lines, language: `python`, fileCategory: `code`)
24. `ai_agent/train_packet_level_agent.py` (112 lines, language: `python`, fileCategory: `code`)
25. `ai_agent/train_packet_level_tcp10.py` (122 lines, language: `python`, fileCategory: `code`)

**Additional context from main session:**

Project: `c2-evasion-rl` — RL agent for C2 traffic evasion against Snort IDS; current system is the 14-mechanism HiddenDefenderEnv trained with MaskablePPO, scored by the real Snort binary. Key subsystems: `ai_agent/` (RL envs + training), `snort_validation/` (real Snort integration, corpus building, evaluation harnesses), `controls/` (correctness controls), `tests/`.

> **Language directive**: Generate all textual content (summaries, descriptions, tags, titles, languageNotes, languageLesson) in **Vietnamese (tiếng Việt)**. Maintain technical accuracy while using natural, native-level phrasing. Keep technical terms in English when no standard translation exists (e.g., "middleware", "hook", "surrogate", "batch").
