Analyze these files and produce GraphNode and GraphEdge objects.

FIRST: Read the agent definition at `/root/.understand-anything-plugin/agents/file-analyzer.md` and follow its output protocol EXACTLY.

Project root: `/root/.hermes/c2-evasion-rl`
Project: `c2-evasion-rl` — RL red-team agent biến đổi gói tin C2 beacon thật để né Snort 2.9.20 (ET Open C2 ruleset), chấm điểm bằng binary Snort thật.
Languages: Python, Bash, Markdown, YAML
Batch: 2/8
Skill directory (for bundled scripts): `/root/.hermes/skills/understand-anything/understand`
Output: write to `/root/.hermes/c2-evasion-rl/.ua/intermediate/batch-2.json` (single-file mode) OR `batch-2-part-<k>.json` (split mode, per Step B of your output protocol).

Pre-resolved import data for this batch (use directly — do NOT re-resolve imports from source):
```json
{"snort_validation/README.md": [], "snort_validation/extract_stratosphere.sh": [], "snort_validation/fetch_stratosphere.sh": [], "snort_validation/fetch_stratosphere_captures.sh": [], "snort_validation/run_stratosphere_sweep.sh": []}
```

Cross-batch neighbors with their exported symbols (confidence boost for cross-batch edges):
```json
{}
```

Files to analyze in this batch (every entry MUST be passed through to `batchFiles` with all four fields — `path`, `language`, `sizeLines`, `fileCategory`):
1. `snort_validation/README.md` (203 lines, language: `markdown`, fileCategory: `docs`)
2. `snort_validation/extract_stratosphere.sh` (22 lines, language: `shell`, fileCategory: `script`)
3. `snort_validation/fetch_stratosphere.sh` (29 lines, language: `shell`, fileCategory: `script`)
4. `snort_validation/fetch_stratosphere_captures.sh` (84 lines, language: `shell`, fileCategory: `script`)
5. `snort_validation/run_stratosphere_sweep.sh` (101 lines, language: `shell`, fileCategory: `script`)

**Additional context from main session:**

Project: `c2-evasion-rl` — RL agent for C2 traffic evasion against Snort IDS; current system is the 14-mechanism HiddenDefenderEnv trained with MaskablePPO, scored by the real Snort binary. Key subsystems: `ai_agent/` (RL envs + training), `snort_validation/` (real Snort integration, corpus building, evaluation harnesses), `controls/` (correctness controls), `tests/`.

> **Language directive**: Generate all textual content (summaries, descriptions, tags, titles, languageNotes, languageLesson) in **Vietnamese (tiếng Việt)**. Maintain technical accuracy while using natural, native-level phrasing. Keep technical terms in English when no standard translation exists (e.g., "middleware", "hook", "surrogate", "batch").
