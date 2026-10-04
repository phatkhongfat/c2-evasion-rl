#!/usr/bin/env python3
"""
Packet-level RL environment for IDS evasion.
Agent modifies individual packets to evade Snort detection.
"""
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import sys
import os

# Import Snort replica
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'snort_validation'))
from snort_query_service import replica_snort_verdict, packet_plan

# Import packet modifier
from packet_modifier import PacketModifier


class PacketLevelEnv(gym.Env):
    """Packet-level IDS evasion environment."""
    
    metadata = {'render.modes': ['human']}
    
    def __init__(
        self,
        malicious_data_pool,
        max_packets_per_flow: int = 50,
        seed: int = None
    ):
        """
        Args:
            malicious_data_pool: List[Dict] of malicious flow samples
            max_packets_per_flow: Maximum packets per episode
            seed: Random seed
        """
        super(PacketLevelEnv, self).__init__()
        
        self.malicious_pool = malicious_data_pool
        self.max_packets = max_packets_per_flow
        self.modifier = PacketModifier(base_ttl=64)
        
        # Action: [ttl_delta, frag_flag, padding_bytes, overlap_offset]
        # Normalized to [-1, 1] for RL training
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(4,), dtype=np.float32
        )
        
        # Observation: [pkt_idx, direction, dsize, time, flow_bytes_sent, flow_pkts_sent, is_detected]
        # - pkt_idx: current packet index / max_packets (normalized)
        # - direction: 0 = src, 1 = dst
        # - dsize: normalized by 1500 (MTU)
        # - time: normalized by flow duration
        # - flow_bytes_sent: cumulative bytes / expected total
        # - flow_pkts_sent: cumulative packets / expected total
        # - is_detected: 0 = not yet, 1 = detected by Snort
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(7,), dtype=np.float32
        )
        
        # Episode state
        self.current_flow = None
        self.current_packets = None
        self.current_pkt_idx = 0
        self.modified_packets = []
        self.is_detected = False
        self.total_reward = 0.0
        
    def reset(self, seed=None, options=None):
        """Start new episode with random malicious flow."""
        super().reset(seed=seed)
        
        # Sample random flow
        idx = self.np_random.integers(0, len(self.malicious_pool))
        self.current_flow = self.malicious_pool[idx].copy()
        
        # Generate packet plan from flow features
        self.current_packets = packet_plan(self.current_flow)
        
        # Limit to max_packets
        if len(self.current_packets) > self.max_packets:
            self.current_packets = self.current_packets[:self.max_packets]
        
        # Reset state
        self.current_pkt_idx = 0
        self.modified_packets = []
        self.is_detected = False
        self.total_reward = 0.0
        
        # Initial observation
        obs = self._get_observation()
        info = {"flow_id": idx, "n_packets": len(self.current_packets)}
        
        return obs, info
    
    def step(self, action):
        """Apply action to current packet, check Snort detection."""
        # Convert normalized action [-1, 1] to actual values
        ttl_delta = action[0] * 10  # ±10 TTL
        frag_flag = action[1]  # >0 = fragment
        padding_bytes = (action[2] + 1) * 100  # 0-200 bytes
        overlap_offset = action[3] * 100  # ±100 bytes
        
        action_vec = np.array([ttl_delta, frag_flag, padding_bytes, overlap_offset])
        
        # Get current packet
        if self.current_pkt_idx >= len(self.current_packets):
            # Episode should have terminated already.
            # NOTE: the info dict here must carry "detected" -- the evaluation
            # script reads info["detected"] on every episode, and flows whose
            # proto yields an empty packet_plan (icmp/rtp) take exactly this
            # path on their first step.  An empty dict raised KeyError.
            return self._get_observation(), 0.0, True, False, {
                "detected": False,
                "packets_sent": self.current_pkt_idx,
                "total_reward": self.total_reward,
            }
        
        current_packet = self.current_packets[self.current_pkt_idx]
        
        # Apply action
        modified = self.modifier.apply_actions([current_packet], [action_vec])[0]
        self.modified_packets.append(modified)
        self.current_pkt_idx += 1
        
        # Check Snort detection after each packet
        flow_features = self.modifier.to_flow_features(self.modified_packets)
        flow_features["proto"] = self.current_flow.get("proto", "tcp")
        flow_features["state"] = self.current_flow.get("state", "CON")
        
        detected = replica_snort_verdict(flow_features)
        
        # Compute reward
        if detected and not self.is_detected:
            # First detection
            reward = -1.0
            self.is_detected = True
        elif not detected and self.current_pkt_idx == len(self.current_packets):
            # Successfully evaded through all packets
            reward = 10.0
        else:
            # Step penalty (encourage efficiency)
            reward = -0.1
        
        self.total_reward += reward
        
        # Episode ends when all packets sent OR detected
        terminated = (self.current_pkt_idx >= len(self.current_packets)) or detected
        truncated = False
        
        # Next observation
        obs = self._get_observation()
        info = {
            "detected": detected,
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
        dsize_norm = min(dsize / 1500.0, 1.0)  # Normalize by MTU
        
        # Flow context
        total_bytes = sum(p["dsize"] for p in self.modified_packets)
        expected_bytes = self.current_flow.get("tot_bytes", 1000)
        bytes_sent_norm = min(total_bytes / max(expected_bytes, 1), 1.0)
        
        pkts_sent_norm = len(self.modified_packets) / max(len(self.current_packets), 1)
        
        # Time normalization (not used in this simple version, set to 0)
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
