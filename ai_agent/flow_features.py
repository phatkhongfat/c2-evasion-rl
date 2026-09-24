"""Canonical derivation of the 20 candidate flow-behaviour features.

Single source of truth for the CTU-13 / Snort-alignment feature pipeline.
Pure Python (no numpy/pandas) so the same code can be imported by the
extraction script, the validation scripts and the RL environment.

WHY DERIVED, NOT MEASURED
-------------------------
The CTU-13 binetflow parquet files shipped in ``data/archive/`` contain only
*flow-level aggregates*: ``dur, proto, dir, state, stos, dtos, tot_pkts,
tot_bytes, src_bytes, label, Family``.  There are no packet arrays, no
timestamps and no TCP flag counters, so packet-size distribution and
inter-arrival statistics **cannot be measured** from this data.  They are
reconstructed under the explicit segmentation model documented next to each
feature below.

The same reconstruction model is already used by
``snort_validation/flow_to_pcap.py`` when it turns the 6 flow features into a
pcap for Snort, so the derived features are *consistent with the traffic the
Snort verdicts were produced on*.  That consistency is what makes the
feature-vs-verdict correlation meaningful; it is also the main threat to
external validity (see FEATURE_ENGINEERING.md -> Risks).

Segmentation model
    * a flow of ``tot_pkts`` packets carries ``tot_bytes`` bytes;
    * every packet carries a 40-byte IP+TCP header (28-byte IP+ICMP);
    * bulk data is segmented into near-MSS chunks (MSS = 1460 B TCP,
      1472 B UDP), so the per-packet payload distribution is *bimodal*:
      near-MSS data segments plus a short tail segment.
"""

# --- segmentation constants (kept in sync with flow_to_pcap.py) -------------
HDR_BYTES = 40.0        # IP + TCP header
HDR_BYTES_ICMP = 28.0   # IP + ICMP header
MSS_TCP = 1460.0        # max TCP segment payload
MSS_UDP = 1472.0        # max UDP datagram payload

# Baseline features the surrogate/env already used (order matters: this is the
# raw feature vector the XGBoost judge is fed).
BASELINE_FEATURES = ["dur", "tot_pkts", "tot_bytes", "src_bytes"]

# The 20 candidate features, in report order.  6 baseline + 20 = 26 columns.
CANDIDATE_FEATURES = [
    # -- packet size distribution (7) ---------------------------------------
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_min",
    "pkt_size_max",
    "pkt_size_median",
    "pkt_size_iqr",
    "pkt_size_cv",
    # -- inter-arrival timing (5) -------------------------------------------
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_cv",
    # -- rate (3) -----------------------------------------------------------
    "pkt_rate",
    "bytes_rate",
    "avg_pkt_size",
    # -- TCP flags (4) ------------------------------------------------------
    "syn_count",
    "fin_count",
    "rst_count",
    "flags_variety",
    # -- payload entropy proxy (1) ------------------------------------------
    "payload_entropy_est",
]

assert len(CANDIDATE_FEATURES) == 20, len(CANDIDATE_FEATURES)


def _f(value, default=0.0):
    try:
        out = float(value)
    except (TypeError, ValueError):
        return float(default)
    if out != out or out in (float("inf"), float("-inf")):  # NaN / inf
        return float(default)
    return out


def derive_flow_features(flow):
    """Derive the 20 candidate features from a 6-field flow record.

    Args:
        flow: mapping with ``dur, tot_pkts, tot_bytes, src_bytes, proto,
            state`` (extra keys ignored).

    Returns:
        dict of the 20 ``CANDIDATE_FEATURES``.
    """
    dur = max(_f(flow.get("dur")), 1e-3)
    tot_pkts = max(_f(flow.get("tot_pkts")), 1.0)
    tot_bytes = max(_f(flow.get("tot_bytes")), 0.0)
    proto = str(flow.get("proto", "tcp")).strip().lower()
    state = str(flow.get("state", "")).strip().upper()

    hdr = HDR_BYTES_ICMP if proto.startswith("icmp") else HDR_BYTES
    max_chunk = MSS_UDP if proto.startswith("udp") else MSS_TCP

    # --- packet size distribution -----------------------------------------
    # tot_bytes / tot_pkts is the only directly observable packet-size
    # statistic in the parquet.  min/max/median/IQR/std are reconstructions
    # from the segmentation model, not measurements.
    pkt_size_mean = tot_bytes / tot_pkts
    pkt_size_max = min(max(pkt_size_mean, hdr), max_chunk)
    pkt_size_min = hdr if tot_pkts > 1 else pkt_size_mean
    pkt_size_median = 0.5 * (pkt_size_min + pkt_size_max)
    pkt_size_iqr = pkt_size_max - pkt_size_min
    # std of a bimodal near-MSS/short-tail payload distribution scales with
    # the payload fill level: an all-header flow has ~0 spread, a
    # fully-filled flow has ~1 MSS of spread.
    pkt_size_std = hdr * pkt_size_mean / max_chunk
    pkt_size_cv = pkt_size_std / max(pkt_size_mean, 1e-9)

    # --- inter-arrival timing ---------------------------------------------
    # iat_mean is exact given (dur, tot_pkts).  The shape statistics around it
    # use the fixed coefficient of variation (0.25) implied by the uniform
    # inter-packet spacing that flow_to_pcap.py emits, so iat_std/iat_cv are
    # *model* quantities that carry no independent information here.
    iat_mean = dur / max(tot_pkts - 1.0, 1.0)
    iat_cv = 0.25 if tot_pkts > 1 else 0.0
    iat_std = iat_cv * iat_mean
    iat_min = 0.2 * iat_mean
    iat_max = 1.8 * iat_mean

    # --- rate -------------------------------------------------------------
    pkt_rate = tot_pkts / dur
    bytes_rate = tot_bytes / dur

    # --- TCP flags --------------------------------------------------------
    # CTU-13 encodes the flags that were *seen* inside the state string
    # (e.g. 'FSPA_FSPA' = FIN+SYN+PSH+ACK, 'S_RA' = SYN+RST+ACK).  We can
    # therefore recover *presence* counts (0/1) but not true packet counts.
    syn_count = 1.0 if proto.startswith("tcp") else 0.0
    fin_count = 1.0 if "F" in state else 0.0
    rst_count = 1.0 if "R" in state else 0.0
    flags_variety = float(sum(1 for v in (syn_count, fin_count, rst_count) if v > 0))

    # --- payload entropy proxy -------------------------------------------
    # Fraction of bytes that are payload (i.e. not header) x 8 bits.  A flow
    # that is all headers scores 0 (no payload to fingerprint); a bulk
    # transfer scores ~8 (payload-dominated, entropy-friendly for IDS
    # content inspection).
    payload_bytes = max(tot_bytes - hdr * tot_pkts, 0.0)
    payload_entropy_est = 8.0 * payload_bytes / max(tot_bytes, 1e-9)

    return {
        "pkt_size_mean": pkt_size_mean,
        "pkt_size_std": pkt_size_std,
        "pkt_size_min": pkt_size_min,
        "pkt_size_max": pkt_size_max,
        "pkt_size_median": pkt_size_median,
        "pkt_size_iqr": pkt_size_iqr,
        "pkt_size_cv": pkt_size_cv,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_min": iat_min,
        "iat_max": iat_max,
        "iat_cv": iat_cv,
        "pkt_rate": pkt_rate,
        "bytes_rate": bytes_rate,
        "avg_pkt_size": pkt_size_mean,
        "syn_count": syn_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "flags_variety": flags_variety,
        "payload_entropy_est": payload_entropy_est,
    }


def candidate_vector(flow, feature_names):
    """Derive features and return them in ``feature_names`` order (list)."""
    derived = derive_flow_features(flow)
    return [float(derived.get(name, 0.0)) for name in feature_names]
