#!/usr/bin/env python3
"""
Packet-level modifications for IDS evasion.
Applies agent actions to packet sequences.
"""
from typing import List, Tuple, Dict
import numpy as np


class PacketModifier:
    """Applies packet-level evasion actions to packet sequences."""
    
    def __init__(self, base_ttl: int = 64):
        """
        Args:
            base_ttl: Default TTL for generated packets
        """
        self.base_ttl = base_ttl
    
    def apply_actions(
        self,
        packets: List[Tuple[str, int, float]],
        actions: List[np.ndarray]
    ) -> List[Dict]:
        """
        Apply agent actions to packet sequence.
        
        Args:
            packets: [(direction, dsize, time), ...] from packet_plan()
            actions: [action_vec, ...] where action_vec = [ttl_delta, frag_flag, padding_bytes, overlap_offset]
        
        Returns:
            List[Dict]: Modified packet metadata with keys:
                - direction: 'src' or 'dst'
                - dsize: payload size (original + padding)
                - time: timestamp
                - ttl: computed TTL
                - fragmented: bool
                - overlap_offset: int (bytes)
        """
        modified_packets = []
        
        for i, ((direction, dsize, time), action) in enumerate(zip(packets, actions)):
            ttl_delta, frag_flag, padding_bytes, overlap_offset = action
            
            # Clamp action values
            ttl_delta = int(np.clip(ttl_delta, -10, 10))  # ±10 TTL variance
            frag_flag = bool(frag_flag > 0)  # Binary fragmentation flag
            padding_bytes = int(np.clip(padding_bytes, 0, 200))  # 0-200 bytes padding
            overlap_offset = int(np.clip(overlap_offset, -100, 100))  # ±100 bytes overlap
            
            modified_packets.append({
                "direction": direction,
                "dsize": dsize + padding_bytes,  # Add padding to payload
                "time": time,
                "ttl": self.base_ttl + ttl_delta,
                "fragmented": frag_flag,
                "overlap_offset": overlap_offset
            })
        
        return modified_packets
    
    def to_flow_features(self, modified_packets: List[Dict]) -> Dict:
        """
        Convert modified packets back to flow-level features for Snort query.
        
        Args:
            modified_packets: Output from apply_actions()
        
        Returns:
            Dict with keys: tot_pkts, tot_bytes, src_bytes, dur
        """
        tot_pkts = len(modified_packets)
        tot_bytes = sum(p["dsize"] for p in modified_packets)
        src_bytes = sum(p["dsize"] for p in modified_packets if p["direction"] == "src")
        dur = modified_packets[-1]["time"] - modified_packets[0]["time"] if len(modified_packets) > 1 else 0.0
        
        return {
            "tot_pkts": tot_pkts,
            "tot_bytes": tot_bytes,
            "src_bytes": src_bytes,
            "dur": dur,
            "proto": "tcp",  # Default to TCP for now
            "state": "CON"   # Default to established
        }
