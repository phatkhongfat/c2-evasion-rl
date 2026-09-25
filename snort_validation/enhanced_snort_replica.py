#!/usr/bin/env python3
"""
Enhanced packet-level Snort replica that considers TTL, fragmentation, and TCP overlap.

This extends replica_snort_verdict to detect evasion attempts via:
- Abnormal TTL values (too low or inconsistent)
- Suspicious fragmentation patterns
- TCP overlap/evasion techniques
"""
from typing import Dict, List
import numpy as np


def enhanced_replica_snort_verdict(
    features: Dict,
    modified_packets: List[Dict] = None
) -> bool:
    """
    Enhanced Snort replica that checks packet-level evasion indicators.
    
    Args:
        features: Flow-level features (tot_pkts, tot_bytes, src_bytes, dur, proto, state)
        modified_packets: List of packet dicts with keys:
            - direction, dsize, time, ttl, fragmented, overlap_offset
    
    Returns:
        True if detected (alert), False if evaded
    """
    # First check the original flow-level rules
    from snort_query_service import replica_snort_verdict
    
    if replica_snort_verdict(features):
        return True  # Caught by flow-level rules
    
    # If no packet metadata provided, can't check packet-level indicators
    if not modified_packets or len(modified_packets) == 0:
        return False
    
    # --- PACKET-LEVEL DETECTION HEURISTICS ---
    
    # Rule P1: Abnormally low TTL (< 10) suggests TTL evasion attempts
    ttls = [p.get("ttl", 64) for p in modified_packets]
    if any(ttl < 10 for ttl in ttls):
        return True
    
    # Rule P2: High TTL variance within a flow (std > 15) is suspicious
    # Real flows from same source should have consistent TTL
    if len(ttls) >= 3 and np.std(ttls) > 15:
        return True
    
    # Rule P3: Excessive fragmentation (>30% of packets) is unusual for normal traffic
    frag_count = sum(1 for p in modified_packets if p.get("fragmented", False))
    if len(modified_packets) >= 5 and frag_count / len(modified_packets) > 0.3:
        return True
    
    # Rule P4: TCP overlap/evasion (large overlap offsets) suggests packet manipulation
    overlaps = [abs(p.get("overlap_offset", 0)) for p in modified_packets]
    if any(overlap > 50 for overlap in overlaps):
        return True
    
    # Rule P5: Combination indicator - multiple suspicious signals together
    # (low TTL + fragmentation + overlap in same flow)
    suspicious_signals = 0
    if min(ttls) < 20:
        suspicious_signals += 1
    if frag_count >= 2:
        suspicious_signals += 1
    if max(overlaps) > 30:
        suspicious_signals += 1
    
    if suspicious_signals >= 2:
        return True
    
    return False


def get_enhanced_detection_reason(
    features: Dict,
    modified_packets: List[Dict] = None
) -> str:
    """
    Return which rule detected the flow (for debugging/analysis).
    
    Returns:
        String like "P1: Low TTL" or "Flow: sid:3000001" or "EVADED"
    """
    from snort_query_service import replica_snort_verdict
    
    if replica_snort_verdict(features):
        return "Flow-level rule"
    
    if not modified_packets or len(modified_packets) == 0:
        return "EVADED (no packet metadata)"
    
    ttls = [p.get("ttl", 64) for p in modified_packets]
    if any(ttl < 10 for ttl in ttls):
        return "P1: Low TTL (<10)"
    
    if len(ttls) >= 3 and np.std(ttls) > 15:
        return f"P2: TTL variance (std={np.std(ttls):.1f})"
    
    frag_count = sum(1 for p in modified_packets if p.get("fragmented", False))
    if len(modified_packets) >= 5 and frag_count / len(modified_packets) > 0.3:
        return f"P3: Excessive fragmentation ({100*frag_count/len(modified_packets):.0f}%)"
    
    overlaps = [abs(p.get("overlap_offset", 0)) for p in modified_packets]
    if any(overlap > 50 for overlap in overlaps):
        return f"P4: Large TCP overlap (max={max(overlaps)})"
    
    suspicious_signals = 0
    if min(ttls) < 20:
        suspicious_signals += 1
    if frag_count >= 2:
        suspicious_signals += 1
    if max(overlaps) > 30:
        suspicious_signals += 1
    
    if suspicious_signals >= 2:
        return f"P5: Multiple suspicious signals ({suspicious_signals})"
    
    return "EVADED"
