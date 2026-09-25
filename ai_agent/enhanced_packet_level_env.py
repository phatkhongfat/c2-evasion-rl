#!/usr/bin/env python3
"""
Enhanced PacketLevelEnv that uses packet-level detection heuristics.
Makes TTL, fragmentation, and TCP overlap actually influence the reward.
"""
import sys
from pathlib import Path
import numpy as np
import gymnasium as gym
from gymnasium import spaces

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from packet_modifier import PacketModifier
from snort_query_service import packet_plan


class EnhancedPacketLevelEnv(gym.Env):
    """Packet-level RL env with enhanced detection (TTL/frag/overlap matter)."""
    
    def __init__(self, malicious_pool, max_packets_per_flow=50, seed=None):
        super().__init__()
        self.malicious_pool = malicious_pool
        self.max_packets_per_flow = max_packets_per_flow
        self.modifier = PacketModifier()
        
        if seed is not None:
            self.seed(seed)
        
        # Action: [ttl_delta, frag_flag, padding_bytes, tcp_overlap] scaled to [-1, 1]
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(4,), dtype=np.float32
        )
        
        # Observation: [pkt_idx, direction, dsize, time, bytes_sent, pkts_sent, is_detected]
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(7,), dtype=np.float32
        )
        
        self.current_flow = None
        self.current_packets = []
        self.modified_packets = []
        self.current_pkt_idx = 0
        self.is_detected = False
        self.total_reward = 0.0
    
    def seed(self, seed=None):
        np.random.seed(seed)
    
    def reset(self, seed=None, options=None):
        if seed is not None:
            self.seed(seed)
        
        # Sample a random flow
        flow_id = np.random.randint(0, len(self.malicious_pool))
        self.current_flow = self.malicious_pool[flow_id].copy()
        
        # Generate packet plan
        self.current_packets = packet_plan(self.current_flow)
        
        # Limit packets
        if len(self.current_packets) > self.max_packets_per_flow:
            self.current_packets = self.current_packets[:self.max_packets_per_flow]
        
        self.modified_packets = []
        self.current_pkt_idx = 0
        self.is_detected = False
        self.total_reward = 0.0
        
        obs = self._get_observation()
        info = {"flow_id": flow_id, "n_packets": len(self.current_packets)}
        
        return obs, info
    
    def step(self, action):
        # Scale action from [-1, 1] to actual ranges
        ttl_delta = action[0] * 10  # ±10
        frag_flag = action[1]  # Keep as-is for >0 check
        padding_bytes = (action[2] + 1) * 100  # [0, 200]
        tcp_overlap = action[3] * 100  # ±100
        
        scaled_action = np.array([ttl_delta, frag_flag, padding_bytes, tcp_overlap])
        
        # Apply to current packet
        if self.current_pkt_idx < len(self.current_packets):
            current_pkt = self.current_packets[self.current_pkt_idx]
            modified = self.modifier.apply_actions([current_pkt], [scaled_action])[0]
            self.modified_packets.append(modified)
            self.current_pkt_idx += 1
        
        # Check if episode is done
        terminated = self.current_pkt_idx >= len(self.current_packets)
        truncated = False
        
        # Compute reward
        if terminated:
            # Episode complete - check detection with ENHANCED replica
            from enhanced_snort_replica import enhanced_replica_snort_verdict
            
            flow_features = self.modifier.to_flow_features(self.modified_packets)
            flow_features["proto"] = self.current_flow.get("proto", "tcp")
            flow_features["state"] = self.current_flow.get("state", "CON")
            
            # Use enhanced replica that considers packet-level features
            detected = enhanced_replica_snort_verdict(flow_features, self.modified_packets)
            self.is_detected = detected
            
            if detected:
                reward = -1.0  # Caught
            else:
                reward = +10.0  # Evaded
        else:
            # Intermediate step - small time penalty
            reward = -0.1
        
        self.total_reward += reward
        
        # Next observation
        obs = self._get_observation()
        info = {
            "detected": self.is_detected if terminated else False,
            "packets_sent": self.current_pkt_idx,
            "total_reward": self.total_reward
        }
        
        return obs, reward, terminated, truncated, info
    
    def _get_observation(self):
        """Build observation vector."""
        if self.current_pkt_idx >= len(self.current_packets):
            # Terminal state
            return np.array([1.0, 0.0, 0.0, 1.0, 1.0, 1.0, float(self.is_detected)], dtype=np.float32)
        
        current_packet = self.current_packets[self.current_pkt_idx]
        direction, dsize, time = current_packet
        
        # Normalize
        pkt_idx_norm = self.current_pkt_idx / max(len(self.current_packets), 1)
        direction_norm = 1.0 if direction == "dst" else 0.0
        dsize_norm = min(dsize / 1500.0, 1.0)
        
        # Flow context
        total_bytes = sum(p["dsize"] for p in self.modified_packets)
        expected_bytes = self.current_flow.get("tot_bytes", 1000)
        bytes_sent_norm = min(total_bytes / max(expected_bytes, 1), 1.0)
        
        pkts_sent_norm = len(self.modified_packets) / max(len(self.current_packets), 1)
        
        time_norm = 0.0
        
        obs = np.array([
            pkt_idx_norm,
            direction_norm,
            dsize_norm,
            time_norm,
            bytes_sent_norm,
            pkts_sent_norm,
            float(self.is_detected)
        ], dtype=np.float32)
        
        return obs
