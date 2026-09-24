# Feature validation vs Snort verdicts

- Samples: **320** (191 positive on `detected`, 59.7%)
- Target: `detected`
- Gate: |Pearson r| > 0.15, p < 0.05, top 10
- Tested 19 features; 17 passed p < 0.05; 12 passed both gates; **10 selected**

> A binary target makes Pearson r the point-biserial correlation; Spearman rho is reported alongside so a monotone-but-nonlinear relationship is not missed.

| # | feature | Pearson r | p | Spearman rho | decision | reason |
|---|---------|-----------|---|--------------|----------|--------|
| 1 | `payload_entropy_est` | -0.5077 | 2.28e-22 | -0.503 | selected | |r|=0.508, p=2.28e-22 |
| 2 | `pkt_size_iqr` | -0.2303 | 3.18e-05 | -0.501 | selected | |r|=0.230, p=3.18e-05 |
| 3 | `pkt_size_min` | +0.2296 | 3.38e-05 | +0.230 | selected | |r|=0.230, p=3.38e-05 |
| 4 | `pkt_size_max` | -0.2271 | 4.12e-05 | -0.491 | selected | |r|=0.227, p=4.12e-05; REDUNDANT with pkt_size_iqr (|r|=1.000) |
| 5 | `pkt_size_median` | -0.2238 | 5.36e-05 | -0.439 | selected | |r|=0.224, p=5.36e-05; REDUNDANT with pkt_size_iqr (|r|=0.999) |
| 6 | `pkt_size_cv` | +0.2215 | 6.45e-05 | -0.051 | selected | |r|=0.221, p=6.45e-05; REDUNDANT with pkt_size_min (|r|=0.997) |
| 7 | `pkt_size_std` | -0.2134 | 0.000119 | -0.368 | selected | |r|=0.213, p=0.000119; REDUNDANT with pkt_size_iqr (|r|=0.979) |
| 8 | `pkt_size_mean` | -0.2130 | 0.000124 | -0.444 | selected | |r|=0.213, p=0.000124; REDUNDANT with pkt_size_iqr (|r|=0.999) |
| 9 | `avg_pkt_size` | -0.2130 | 0.000124 | -0.444 | selected | |r|=0.213, p=0.000124; REDUNDANT with pkt_size_iqr (|r|=0.999) |
| 10 | `rst_count` | +0.1893 | 0.000663 | +0.189 | selected | |r|=0.189, p=0.000663 |
| 11 | `pkt_rate` | +0.1712 | 0.00212 | +0.593 | reject | |r|=0.171 passes gate but ranked below top 10 |
| 12 | `bytes_rate` | +0.1579 | 0.00463 | +0.597 | reject | |r|=0.158 passes gate but ranked below top 10 |
| 13 | `iat_max` | -0.1296 | 0.0204 | -0.629 | reject | |r|=0.130 <= 0.15 (effect-size floor) |
| 14 | `iat_std` | -0.1296 | 0.0204 | -0.629 | reject | |r|=0.130 <= 0.15 (effect-size floor) |
| 15 | `iat_mean` | -0.1296 | 0.0204 | -0.629 | reject | |r|=0.130 <= 0.15 (effect-size floor) |
| 16 | `iat_min` | -0.1296 | 0.0204 | -0.629 | reject | |r|=0.130 <= 0.15 (effect-size floor) |
| 17 | `fin_count` | +0.1278 | 0.0222 | +0.128 | reject | |r|=0.128 <= 0.15 (effect-size floor) |
| 18 | `flags_variety` | +0.0943 | 0.0921 | +0.085 | reject | |r|=0.094 <= 0.15 (effect-size floor) |
| 19 | `syn_count` | -0.0576 | 0.305 | -0.058 | reject | |r|=0.058 <= 0.15 (effect-size floor) |
| 20 | `iat_cv` | n/a | n/a | n/a | reject | degenerate (zero variance) |

## Selected feature set (literal gate)

```
["payload_entropy_est", "pkt_size_iqr", "pkt_size_min", "pkt_size_max", "pkt_size_median", "pkt_size_cv", "pkt_size_std", "pkt_size_mean", "avg_pkt_size", "rst_count"]
```

## Collinearity-deduplicated set

```
["payload_entropy_est", "pkt_size_iqr", "pkt_size_min", "rst_count", "pkt_rate"]
```

## Redundancy inside the literal selected set (16 pairs with |r| >= 0.95)

| feature A | feature B | r |
|-----------|-----------|---|
| `pkt_size_iqr` | `pkt_size_max` | +0.9998 |
| `pkt_size_iqr` | `pkt_size_median` | +0.9993 |
| `pkt_size_iqr` | `pkt_size_std` | +0.9787 |
| `pkt_size_iqr` | `pkt_size_mean` | +0.9987 |
| `pkt_size_iqr` | `avg_pkt_size` | +0.9987 |
| `pkt_size_min` | `pkt_size_cv` | +0.9973 |
| `pkt_size_max` | `pkt_size_median` | +0.9998 |
| `pkt_size_max` | `pkt_size_std` | +0.9805 |
| `pkt_size_max` | `pkt_size_mean` | +0.9989 |
| `pkt_size_max` | `avg_pkt_size` | +0.9989 |
| `pkt_size_median` | `pkt_size_std` | +0.9820 |
| `pkt_size_median` | `pkt_size_mean` | +0.9987 |
| `pkt_size_median` | `avg_pkt_size` | +0.9987 |
| `pkt_size_std` | `pkt_size_mean` | +0.9826 |
| `pkt_size_std` | `avg_pkt_size` | +0.9826 |
| `pkt_size_mean` | `avg_pkt_size` | +1.0000 |

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
    "pkt_size_iqr": 0.64,
    "pkt_size_min": -0.184,
    "pkt_size_max": 0.639,
    "pkt_size_median": 0.639,
    "pkt_size_cv": -0.184,
    "pkt_size_std": 0.696,
    "pkt_size_mean": 0.653,
    "avg_pkt_size": 0.653,
    "rst_count": 0.012
  },
  "pkt_size_iqr": {
    "payload_entropy_est": 0.64,
    "pkt_size_iqr": 1.0,
    "pkt_size_min": -0.264,
    "pkt_size_max": 1.0,
    "pkt_size_median": 0.999,
    "pkt_size_cv": -0.264,
    "pkt_size_std": 0.979,
    "pkt_size_mean": 0.999,
    "avg_pkt_size": 0.999,
    "rst_count": -0.067
  },
  "pkt_size_min": {
    "payload_entropy_est": -0.184,
    "pkt_size_iqr": -0.264,
    "pkt_size_min": 1.0,
    "pkt_size_max": -0.247,
    "pkt_size_median": -0.229,
    "pkt_size_cv": 0.997,
    "pkt_size_std": -0.156,
    "pkt_size_mean": -0.248,
    "avg_pkt_size": -0.248,
    "rst_count": 0.07
  },
  "pkt_size_max": {
    "payload_entropy_est": 0.639,
    "pkt_size_iqr": 1.0,
    "pkt_size_min": -0.247,
    "pkt_size_max": 1.0,
    "pkt_size_median": 1.0,
    "pkt_size_cv": -0.247,
    "pkt_size_std": 0.981,
    "pkt_size_mean": 0.999,
    "avg_pkt_size": 0.999,
    "rst_count": -0.066
  },
  "pkt_size_median": {
    "payload_entropy_est": 0.639,
    "pkt_size_iqr": 0.999,
    "pkt_size_min": -0.229,
    "pkt_size_max": 1.0,
    "pkt_size_median": 1.0,
    "pkt_size_cv": -0.229,
    "pkt_size_std": 0.982,
    "pkt_size_mean": 0.999,
    "avg_pkt_size": 0.999,
    "rst_count": -0.065
  },
  "pkt_size_cv": {
    "payload_entropy_est": -0.184,
    "pkt_size_iqr": -0.264,
    "pkt_size_min": 0.997,
    "pkt_size_max": -0.247,
    "pkt_size_median": -0.229,
    "pkt_size_cv": 1.0,
    "pkt_size_std": -0.157,
    "pkt_size_mean": -0.249,
    "avg_pkt_size": -0.249,
    "rst_count": 0.081
  },
  "pkt_size_std": {
    "payload_entropy_est": 0.696,
    "pkt_size_iqr": 0.979,
    "pkt_size_min": -0.156,
    "pkt_size_max": 0.981,
    "pkt_size_median": 0.982,
    "pkt_size_cv": -0.157,
    "pkt_size_std": 1.0,
    "pkt_size_mean": 0.983,
    "avg_pkt_size": 0.983,
    "rst_count": -0.061
  },
  "pkt_size_mean": {
    "payload_entropy_est": 0.653,
    "pkt_size_iqr": 0.999,
    "pkt_size_min": -0.248,
    "pkt_size_max": 0.999,
    "pkt_size_median": 0.999,
    "pkt_size_cv": -0.249,
    "pkt_size_std": 0.983,
    "pkt_size_mean": 1.0,
    "avg_pkt_size": 1.0,
    "rst_count": -0.061
  },
  "avg_pkt_size": {
    "payload_entropy_est": 0.653,
    "pkt_size_iqr": 0.999,
    "pkt_size_min": -0.248,
    "pkt_size_max": 0.999,
    "pkt_size_median": 0.999,
    "pkt_size_cv": -0.249,
    "pkt_size_std": 0.983,
    "pkt_size_mean": 1.0,
    "avg_pkt_size": 1.0,
    "rst_count": -0.061
  },
  "rst_count": {
    "payload_entropy_est": 0.012,
    "pkt_size_iqr": -0.067,
    "pkt_size_min": 0.07,
    "pkt_size_max": -0.066,
    "pkt_size_median": -0.065,
    "pkt_size_cv": 0.081,
    "pkt_size_std": -0.061,
    "pkt_size_mean": -0.061,
    "avg_pkt_size": -0.061,
    "rst_count": 1.0
  }
}
```
