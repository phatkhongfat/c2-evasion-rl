# Plan: resolve "naive ≡ expert" (ceiling test cannot distinguish rulesets)

## Goal
Make the evasion benchmark discriminating: build a multi-family test corpus on which the 21k-rule expert set fires measurably more SIDs than the 4-rule naive set, then re-run ceiling + PPO on it.

## Current context (verified, 2026-10-08/10)
- Repo `/root/.hermes/c2-evasion-rl`, branch `packet-level-rl`, HEAD `ba35b4d`. ALWAYS run commands with explicit workdir (plain terminal cwd goes stale).
- Corpus: `snort_validation/reports/hidden_defender_corpus.pkl` (dict; `d['test']` = 40 flows, each `{flow_id, packets,...}`), split logic `snort_validation/corpus_config.py` (N_TEST=40, SEED=42). Only 2 captures contribute: CTU-13 `neris-20110811` (16 FakeAV HTTP flows) and `bot-20110819` (24 UDP DHT flows).
- Real-Snort result: union of fired SIDs on ALL 21,374 expert rules = also on full ET Open 52,317 rules = `{2008581,2008583,2008585,2012627}` = exactly the 4-rule naive set (`snort_validation/et_open_c2/naive.rules`). So per-mechanism evaded/valid is identical for naive and expert (14/14).
- Root cause (NOT a bug): load OK (21,374 enabled), http_inspect adds 0 SIDs, orphan flowbits irrelevant. 7,622/7,723 UDP rules target dst port 53; only 49 applicable rules have all contents present and each is blocked by pcre/dsize/offset/flowbits/stream_size. Corpus is simply single-family-poor.
- Unused assets: `CAPTURES` in `corpus_config.py` lists `stratosphere 20110810-neris` and `cybersure-win capture-win13` (not in corpus); `data/datasets_eval/unsw-nb15`; `snort_validation/pcaps` (555M); fetch scripts `fetch_stratosphere*.sh`.
- Constraint: never edit the bar/probe to keep 100%; report numbers that drop. Do not touch `snort_et_c2.conf`.

## Approach
Diagnose which candidate captures give ET-detectable, diverse traffic BEFORE any RL: run baseline Snort (expert conf, then naive conf) over every candidate pcap, keep families where expert fires SIDs outside the naive 4. Build a new corpus `hidden_defender_corpus_v3.pkl` from those, then re-run the existing ceiling sweep (`controls/ownership_ceiling_sweep.py --conf`) for both tiers and compare. Success is a *measured* gap (or an honest, documented "still equal").

## Tasks

### T1 — Coverage probe (read-only script, new `controls/coverage_probe.py`)
For each pcap in `snort_validation/pcaps` and any file `fetch_*.sh` can obtain: run `snort -r <pcap> -c snort_validation/et_open_c2/snort_et_c2.conf -A none -l /tmp/cov/<name>` and again with `snort_et_c2_naive.conf`; parse alert SIDs. Output `snort_validation/reports/coverage_probe.json`: per pcap `{expert_sids, naive_sids, extra_sids=expert−naive, n_alerts}`.
- Verify: `.venv/bin/python controls/coverage_probe.py && python -c "import json;d=json.load(open('snort_validation/reports/coverage_probe.json'));print({k:len(v['extra_sids']) for k,v in d.items()})"` prints a dict; at least one pcap with `extra_sids>0` is the acceptance gate for T2.
- Test (write first): `tests/test_coverage_probe.py` — feed a tiny synthetic alert_fast text, assert extra_sids = set difference.

### T2 — Gate decision
- If ≥2 families have `extra_sids>0`: proceed T3.
- If none: stop; fetch more captures (T2b) from public CTU-13 other scenarios (e.g. 42/43/46/47 families: Virut, Menti, Murlo, Sogou) via `fetch_stratosphere_captures.sh`, or Malware-Traffic-Analysis pcaps; rerun T1. If still none, record negative result in `docs/THREAT_MODEL.md` and finish at T7 (honest outcome).

### T3 — Corpus builder v3 (new `snort_validation/build_corpus_v3.py`, reuse `corpus_config.split_flows`)
Select only flows whose baseline real-Snort verdict = ALERT under expert conf (same rule as v1: positives only). Stratify: ≥10 flows per family, cap per family so no family >40%. Keep N_TEST=40, SEED=42. Write `hidden_defender_corpus_v3.pkl` with same schema (`train`,`test`, flow `{flow_id,packets}`) so `score_flow_real`/`client_ip_of` work unchanged.
- Test: `tests/test_corpus_v3.py` — schema keys, len(test)==40, no flow_id overlap train/test, ≥3 distinct capture prefixes in test.

### T4 — Add `--corpus` flag to sweep (small patch to `controls/ownership_ceiling_sweep.py`)
Default stays v1 path (backward compat; existing tests must still pass: `.venv/bin/python -m pytest -q` → 123 passed). Test in `tests/test_sweep_conf_flag.py` style: parser accepts `--corpus`.

### T5 — Re-run baseline + ceiling, both tiers (background, `terminal(background=true)`; each run exceeds 300s)
```
.venv/bin/python controls/ownership_ceiling_sweep.py --ownership both --corpus snort_validation/reports/hidden_defender_corpus_v3.pkl --conf snort_validation/et_open_c2/snort_et_c2.conf       --out snort_validation/reports/ceiling_expert_v3.json
.venv/bin/python controls/ownership_ceiling_sweep.py --ownership both --corpus ...v3.pkl --conf snort_validation/et_open_c2/snort_et_c2_naive.conf --out snort_validation/reports/ceiling_naive_v3.json
```
Compare per-mechanism evaded/valid. Expected if hypothesis true: expert evaded < naive evaded on ≥1 mechanism (expert catches things naive misses). Report whatever comes out; do NOT adjust bar/probe.

### T6 — Retrain PPO on v3 (3 seeds 7/1337/42) only if T5 shows a gap
Reuse existing training command for `ai_agent/hidden_defender_env.py` with corpus path param; evaluate with real Snort under expert conf. Record test evasion% per seed and learning-curve CSV via `controls/learning_curves.py`.

### T7 — Document and commit (separate commits)
1. `docs/THREAT_MODEL.md`: add section "naive vs expert" with root cause (above), coverage_probe table, v3 results or the negative result.
2. Commit `snort_et_c2_httpinspect.conf` only as validation artifact (note: adds 0 SIDs) — or delete it; user's call.
3. `git add` explicit paths only; do NOT `git add -A` (worktree has 4 deleted `logs/training_*.json` + modified `ppo_hidden_defender.json` + thesis files that are unrelated).

## Validation
- `.venv/bin/python -m pytest -q` → ≥123 passed + new tests, 0 failed.
- `snort_validation/reports/coverage_probe.json` shows `extra_sids` per pcap.
- Final claim tied to a number: "expert − naive evaded gap = X on v3" or "no gap on N families".

## Risks / open questions
- Public captures may not trigger ET C2 rules (ET targets known samples; 2011 CTU-13 is old). Gap may stay 0 → that is a valid result, document it.
- Larger/more diverse corpus will likely LOWER the 100% ceiling (fragmentation may not evade stateful/pcre rules) — expected, report it.
- PCAP licence/size and fetch availability on the VPS (network access unverified).
- Open Q for user: (a) accept negative result if no discriminating pcap exists? (b) allow crafting synthetic flows from ET rule contents (replaying rule `content:` strings) as a fallback — gives coverage but is synthetic, weaker as evidence.
- Open Q: what to do with the 4 deleted `logs/training_*.json` (restore with `git checkout -- logs/` unless intentional).

## Addendum — ruleset research (T0, added on user request)
Purpose: test the second half of the hypothesis. Naive==expert may come from (a) poor corpus (T1-T6) AND/OR (b) ET Open simply lacking signatures for 2011 CTU-13 families. T0 checks (b) with other free rulesets before building corpora.

### T0 — Candidate rulesets (web research, 2026-10-10)
- Snort Community rules (free, GPL, https://www.snort.org/downloads) — ~4k rules, includes malware-cnc/botnet files. Native Snort 2.9 syntax: lowest conversion risk.
- Snort Talos Registered/Subscriber — needs registration/paid; check whether 30-day-delayed registered set is obtainable. Needs user's account: ASK, never guess credentials.
- Abuse.ch Feodo/SSLBL "Botnet C2 IP" ruleset (https://sslbl.abuse.ch/blacklist/sslipblacklist.rules) — usable by Snort AND Suricata, but IP-based and DEPRECATED 2025-01-03; also 2011 IPs not in it. Expected: 0 extra. Low priority; include only for completeness.
- ET Pro — commercial, skip.
- Note: ET Open rule *history* (older snapshots, e.g. 2011-2013 releases) likely contains signatures for Neris/Rbot/Virut that were later pruned. Check https://rules.emergingthreats.net/ archive or Wayback; this is the highest-yield option for CTU-13 (2011).

### T0 tasks
1. Create `/tmp/rs/` and download Snort community rules + archived ET Open snapshot (2012-ish) with `curl -fLo`; record URL, date, sha256 in `snort_validation/rulesets/SOURCES.md` (new). Expected: files exist, sha256 printed.
2. Convert/validate each: copy to `snort_validation/rulesets/<name>/`, make a conf from `snort_et_c2.conf` (change only the `include` lines), run `snort -T -c <conf>`; expect "Snort successfully validated the configuration" and N rules loaded. Unsupported keywords -> drop that rule and log count (do not hand-edit rules).
3. Run baseline Snort on the existing 40-flow corpus per ruleset (reuse `/tmp/cmp_full_et.py` pattern; copy it into `controls/ruleset_probe.py` with `--conf` arg). Output `snort_validation/reports/ruleset_probe.json`: per ruleset `{rules_loaded, fired_sids, extra_vs_naive}`.
   - Verify: command prints one line per ruleset. Gate: any ruleset with `extra_vs_naive` non-empty on the existing corpus = naive!=expert already resolved by ruleset, corpus change optional.
4. Add the same rulesets as extra columns in T1 coverage probe (`coverage_probe.py` takes repeated `--conf`).
5. Ceiling comparison in T5 then runs naive vs ET-expert vs best alternate ruleset.

### Constraints
- Do not modify `snort_et_c2.conf`; new confs are separate files.
- Rule files keep original SIDs; document the licence of each in SOURCES.md.
- Honest outcome allowed: all rulesets fire the same 4 SIDs => record as negative result.
