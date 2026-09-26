# Known measurement caveat — cross-capture eval (2026-09-26)

Status: **open, unfixed, deliberately not in README** (user decision 2026-09-26).
Recorded here so the fact is not lost.

## What

`data/mcfp_snost_labeled.parquet` (the MCFP table loaded by
`ai_agent/eval_cross_capture.py`) does not carry the columns the env reads:

| env reads | key used | present in parquet? | fallback used |
|---|---|---|---|
| packet duration | `dur` | no | `1.0` |
| source-side bytes | `src_bytes` | no | `500` |
| TCP state | `state` | no | `"CON"` |

The env's `_clamp_features` / `packet_plan` read these with `.get(k, default)`,
so every eval flow is scored against a packet plan built from **constant
default features**, not the flow's real measurements. No warning is emitted.

## Measured impact

Running the same trained checkpoint over the same 50 flows:

- as-shipped (raw MCFP records, defaults substituted) → agent evasion **0.80**, baseline 0.06
- with MCFP columns mapped onto the env schema → agent evasion **0.84**

So the reported number is **lower** than the correctly-mapped one. Omitting the
caveat from the README therefore does not overstate the result — the direction
of the error is favourable. That was a factor in the decision not to carry it
into the README.

## Reference implementation that maps correctly

`ai_agent/real_packet_env.py` (lines 55–140) performs the MCFP → env-schema
mapping. The new eval path skips it.

## Why it still matters

The measurement does not measure what the label claims. A 0.82 evasion figure
labelled "cross-capture generalisation" was produced against synthetic packet
plans. It is a real number for a well-defined but *different* experiment than
the one the report names.

## Fix sketch (not implemented — separate plan, user deferred)

In `ai_agent/eval_cross_capture.py::main()`, map the MCFP columns onto the env
schema before building the pools, mirroring `real_packet_env.py`:

```python
def to_env_schema(rec: dict) -> dict:
    return {
        "flow_tag": rec.get("flow_tag"),
        "tot_pkts": rec.get("tot_pkts", 10),
        "tot_bytes": rec.get("tot_bytes", 1000),
        "src_bytes": rec.get("fwd_bytes", 500),        # was falling back to 500
        "dur": rec.get("flow_duration", 1.0),           # was falling back to 1.0
        "proto": rec.get("proto", "tcp"),
        "state": rec.get("state", "CON"),
    }

train_pool = [to_env_schema(r) for r in df[df['capture'] == train_capture].to_dict('records')]
eval_pool  = [to_env_schema(r) for r in df[df['capture'] == eval_capture].to_dict('records')]
```

Then regenerate `snort_validation/reports/cross_capture_eval.json` and update
any README numbers derived from it. The determinism tests in
`tests/test_eval_cross_capture_determinism.py` should continue to pass — the
fix does not touch the seeding.

## Verification command for the fix

```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python ai_agent/eval_cross_capture.py 2>&1 | tail -7
.venv/bin/python -m pytest tests/test_eval_cross_capture_determinism.py -q
```
Expect the report sha256 to be stable across runs, and agent evasion to read
0.84 rather than 0.82.
