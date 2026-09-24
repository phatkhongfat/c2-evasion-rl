# Feature validation vs the XGBoost judge verdict

- Samples: **320** (206 positive on `run_xgb_evaded`, 64.4%)
- Target: `run_xgb_evaded`
- Gate: |Pearson r| > 0.15, p < 0.05, top 10
- Tested 19 features; 13 passed p < 0.05; 9 passed both gates; **9 selected**

> A binary target makes Pearson r the point-biserial correlation; Spearman rho is reported alongside so a monotone-but-nonlinear relationship is not missed.

| # | feature | Pearson r | p | Spearman rho | decision | reason |
|---|---------|-----------|---|--------------|----------|--------|
| 1 | `payload_entropy_est` | -0.4934 | 4.86e-21 | -0.520 | selected | |r|=0.493, p=4.86e-21 |
| 2 | `pkt_size_std` | -0.2801 | 3.52e-07 | -0.428 | selected | |r|=0.280, p=3.52e-07 |
| 3 | `pkt_size_mean` | -0.2736 | 6.68e-07 | -0.507 | selected | |r|=0.274, p=6.68e-07; REDUNDANT with pkt_size_std (|r|=0.983) |
| 4 | `avg_pkt_size` | -0.2736 | 6.68e-07 | -0.507 | selected | |r|=0.274, p=6.68e-07; REDUNDANT with pkt_size_std (|r|=0.983) |
| 5 | `pkt_size_iqr` | -0.2672 | 1.23e-06 | -0.518 | selected | |r|=0.267, p=1.23e-06; REDUNDANT with pkt_size_std (|r|=0.979) |
| 6 | `pkt_size_max` | -0.2637 | 1.71e-06 | -0.511 | selected | |r|=0.264, p=1.71e-06; REDUNDANT with pkt_size_std (|r|=0.981) |
| 7 | `pkt_size_median` | -0.2601 | 2.4e-06 | -0.471 | selected | |r|=0.260, p=2.4e-06; REDUNDANT with pkt_size_std (|r|=0.982) |
| 8 | `pkt_size_min` | +0.2536 | 4.34e-06 | +0.254 | selected | |r|=0.254, p=4.34e-06 |
| 9 | `pkt_size_cv` | +0.2526 | 4.75e-06 | +0.065 | selected | |r|=0.253, p=4.75e-06; REDUNDANT with pkt_size_min (|r|=0.997) |
| 10 | `iat_mean` | -0.1258 | 0.0244 | -0.665 | reject | |r|=0.126 <= 0.15 (effect-size floor) |
| 11 | `iat_std` | -0.1258 | 0.0244 | -0.665 | reject | |r|=0.126 <= 0.15 (effect-size floor) |
| 12 | `iat_max` | -0.1258 | 0.0244 | -0.665 | reject | |r|=0.126 <= 0.15 (effect-size floor) |
| 13 | `iat_min` | -0.1258 | 0.0244 | -0.665 | reject | |r|=0.126 <= 0.15 (effect-size floor) |
| 14 | `rst_count` | +0.0777 | 0.166 | +0.078 | reject | |r|=0.078 <= 0.15 (effect-size floor) |
| 15 | `flags_variety` | +0.0576 | 0.304 | +0.071 | reject | |r|=0.058 <= 0.15 (effect-size floor) |
| 16 | `bytes_rate` | -0.0451 | 0.421 | +0.640 | reject | |r|=0.045 <= 0.15 (effect-size floor) |
| 17 | `syn_count` | +0.0420 | 0.454 | +0.042 | reject | |r|=0.042 <= 0.15 (effect-size floor) |
| 18 | `pkt_rate` | -0.0310 | 0.581 | +0.665 | reject | |r|=0.031 <= 0.15 (effect-size floor) |
| 19 | `fin_count` | -0.0176 | 0.754 | -0.018 | reject | |r|=0.018 <= 0.15 (effect-size floor) |
| 20 | `iat_cv` | n/a | n/a | n/a | reject | degenerate (zero variance) |

## Selected feature set (literal gate)

```
["payload_entropy_est", "pkt_size_std", "pkt_size_mean", "avg_pkt_size", "pkt_size_iqr", "pkt_size_max", "pkt_size_median", "pkt_size_min", "pkt_size_cv"]
```

## Collinearity-deduplicated set

```
["payload_entropy_est", "pkt_size_std", "pkt_size_min"]
```

## Redundancy inside the literal selected set (16 pairs with |r| >= 0.95)

| feature A | feature B | r |
|-----------|-----------|---|
| `pkt_size_std` | `pkt_size_mean` | +0.9826 |
| `pkt_size_std` | `avg_pkt_size` | +0.9826 |
| `pkt_size_std` | `pkt_size_iqr` | +0.9787 |
| `pkt_size_std` | `pkt_size_max` | +0.9805 |
| `pkt_size_std` | `pkt_size_median` | +0.9820 |
| `pkt_size_mean` | `avg_pkt_size` | +1.0000 |
| `pkt_size_mean` | `pkt_size_iqr` | +0.9987 |
| `pkt_size_mean` | `pkt_size_max` | +0.9989 |
| `pkt_size_mean` | `pkt_size_median` | +0.9987 |
| `avg_pkt_size` | `pkt_size_iqr` | +0.9987 |
| `avg_pkt_size` | `pkt_size_max` | +0.9989 |
| `avg_pkt_size` | `pkt_size_median` | +0.9987 |
| `pkt_size_iqr` | `pkt_size_max` | +0.9998 |
| `pkt_size_iqr` | `pkt_size_median` | +0.9993 |
| `pkt_size_max` | `pkt_size_median` | +0.9998 |
| `pkt_size_min` | `pkt_size_cv` | +0.9973 |

The literal top-10 is dominated by one signal: the packet-size family is 9 algebraic restatements of `tot_bytes / tot_pkts` (`avg_pkt_size` is a literal alias of `pkt_size_mean`). Only `payload_entropy_est`, `pkt_size_iqr`, `pkt_size_min` and `rst_count` survive de-duplication. The literal set is kept as the training set because that is what the plan specified, but any claim that 10 features add 10 features' worth of signal would be wrong.

## Baseline (control) features

```
["dur", "tot_pkts", "tot_bytes", "src_bytes", "proto_encoded", "state_encoded"]
```

## Selected-feature correlation matrix

```json
{
  "payload_entropy_est": {
    "payload_entropy_est": 1.0,
    "pkt_size_std": 0.696,
    "pkt_size_mean": 0.653,
    "avg_pkt_size": 0.653,
    "pkt_size_iqr": 0.64,
    "pkt_size_max": 0.639,
    "pkt_size_median": 0.639,
    "pkt_size_min": -0.184,
    "pkt_size_cv": -0.184
  },
  "pkt_size_std": {
    "payload_entropy_est": 0.696,
    "pkt_size_std": 1.0,
    "pkt_size_mean": 0.983,
    "avg_pkt_size": 0.983,
    "pkt_size_iqr": 0.979,
    "pkt_size_max": 0.981,
    "pkt_size_median": 0.982,
    "pkt_size_min": -0.156,
    "pkt_size_cv": -0.157
  },
  "pkt_size_mean": {
    "payload_entropy_est": 0.653,
    "pkt_size_std": 0.983,
    "pkt_size_mean": 1.0,
    "avg_pkt_size": 1.0,
    "pkt_size_iqr": 0.999,
    "pkt_size_max": 0.999,
    "pkt_size_median": 0.999,
    "pkt_size_min": -0.248,
    "pkt_size_cv": -0.249
  },
  "avg_pkt_size": {
    "payload_entropy_est": 0.653,
    "pkt_size_std": 0.983,
    "pkt_size_mean": 1.0,
    "avg_pkt_size": 1.0,
    "pkt_size_iqr": 0.999,
    "pkt_size_max": 0.999,
    "pkt_size_median": 0.999,
    "pkt_size_min": -0.248,
    "pkt_size_cv": -0.249
  },
  "pkt_size_iqr": {
    "payload_entropy_est": 0.64,
    "pkt_size_std": 0.979,
    "pkt_size_mean": 0.999,
    "avg_pkt_size": 0.999,
    "pkt_size_iqr": 1.0,
    "pkt_size_max": 1.0,
    "pkt_size_median": 0.999,
    "pkt_size_min": -0.264,
    "pkt_size_cv": -0.264
  },
  "pkt_size_max": {
    "payload_entropy_est": 0.639,
    "pkt_size_std": 0.981,
    "pkt_size_mean": 0.999,
    "avg_pkt_size": 0.999,
    "pkt_size_iqr": 1.0,
    "pkt_size_max": 1.0,
    "pkt_size_median": 1.0,
    "pkt_size_min": -0.247,
    "pkt_size_cv": -0.247
  },
  "pkt_size_median": {
    "payload_entropy_est": 0.639,
    "pkt_size_std": 0.982,
    "pkt_size_mean": 0.999,
    "avg_pkt_size": 0.999,
    "pkt_size_iqr": 0.999,
    "pkt_size_max": 1.0,
    "pkt_size_median": 1.0,
    "pkt_size_min": -0.229,
    "pkt_size_cv": -0.229
  },
  "pkt_size_min": {
    "payload_entropy_est": -0.184,
    "pkt_size_std": -0.156,
    "pkt_size_mean": -0.248,
    "avg_pkt_size": -0.248,
    "pkt_size_iqr": -0.264,
    "pkt_size_max": -0.247,
    "pkt_size_median": -0.229,
    "pkt_size_min": 1.0,
    "pkt_size_cv": 0.997
  },
  "pkt_size_cv": {
    "payload_entropy_est": -0.184,
    "pkt_size_std": -0.157,
    "pkt_size_mean": -0.249,
    "avg_pkt_size": -0.249,
    "pkt_size_iqr": -0.264,
    "pkt_size_max": -0.247,
    "pkt_size_median": -0.229,
    "pkt_size_min": 0.997,
    "pkt_size_cv": 1.0
  }
}
```
