# Ponytail audit — Stratosphere sweep (Task 4.1)

Audit rules: the ladder (YAGNI → already here → stdlib → native → installed dep
→ one line → minimum code). Tags: `delete`, `stdlib`, `native`, `yagni`,
`shrink`. Scope is over-engineering only; correctness bugs are called out
separately as blockers.

## Findings

1. `yagni` three per-experiment wrapper scripts (`cross_capture_validation.py`,
   `sweep_corrupt_cost.py`, `scale_flows.py`) that each `subprocess.run`
   `snort_bandit.py` and then scrape the JSON out of its **stdout**.
   `ai_agent/snort_bandit.py` now takes `--sweep-cost/--scale-flows/--captures`
   and writes the reports itself; the wrappers were deleted (~120 lines).
2. `yagni` the sibling's cross-capture wrapper did not merely wrap: it
   **fabricated** its verdicts (`evaded += np.random.randint(...)`, plus a
   `# mock for now` comment) while calling itself validation. A mock that
   produces the headline table is worse than no script. Deleted; the bandit's
   `--captures` path queries real Snort. **Blocker, not style.**
3. `shrink` three near-identical experiment loops (load env → run → collect)
   → one `run_configs()` over `(capture, n_flows, corrupt_cost)` tuples.
   Env caching inside it is required, not a convenience: the cost sweep must
   compare costs on *identical* flows.
4. `shrink` `_capture_dir_for()` re-globbed the capture root and then re-built
   the pcap path. Now `_capture_pcap(capture, dataset)` is the single locator,
   and `_capture_dir_for` is its `.parent` (one definition of "where is this
   capture", so `dataset=` routing cannot disagree with the loader).
5. `native` `--pattern` glob on the existing extractors instead of a new MCFP
   extractor. The tested `extract_pcap()`/`load_labels()` already do the work;
   the only thing blocking them was a hard-coded `botnet-capture-*` glob.
   Reused → no second feature-extraction implementation to keep in sync.
6. `stdlib` atomic report writes via `Path.with_suffix('.tmp')` + `Path.replace`
   (atomic on the same filesystem) rather than a `tempfile` + `shutil.move`
   dance, and one shared `write_json_atomic()` instead of a copy per script.
7. `delete` `--flows`'s implicit float conversion path and the sibling's
   `evasion_pct` defaulting. Aggregation now **fails** on a missing
   `evasion_pct`/`mean_corrupt` instead of substituting `0`: a failed run
   silently read as "evaded nothing", which is a fabricated data point.
8. `delete` per-packet `n_corrupt` accounting replaced by `corrupt_targets()`:
   the old code charged `masks.sum()` (mask *slots*) while the mutator only
   corrupts packets that *have a payload*, so the cost sweep was not measuring
   the cost it was charging.
9. `native` `statistics.mean/pstdev` instead of a hand-rolled mean/std.

## Not cut (deliberately)

- The resident-vs-batch fallback: the resident service needs `CAP_NET_RAW` and
  `lo`, and without the fallback every run dies in a container that lacks them.
- Per-query unique source addresses (`_uid_to_addr_port`): ET rules carry
  `threshold: type limit, track by_src`, so reusing an address silently
  suppresses alerts. Looks like needless uniqueness; it is load-bearing.
- `restart()` on the resident service: the plan requires the loops to survive
  a Snort crash, and the query-id counter must NOT reset across a restart for
  the same throttle reason.

## LOC

- Deleted: 3 wrapper scripts + `run_stratosphere_plan.sh` ≈ 330 lines (incl. the mock).
- `snort_bandit.py`: 297 → 447 lines, but that is one file absorbing three
  experiment modes, real `--dataset`/`--captures` routing, crash-retry, and
  payload-aware cost accounting that previously did not exist at all.
- `aggregate_results.py`: 80 → 176 (missing-value failures, cross-capture
  mean/std, table printing).

net: −330 lines of wrapper, +3 dependencies: none.
