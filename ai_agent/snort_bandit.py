#!/usr/bin/env python3
"""
Batched bandit: learn WHICH packets to corrupt, one Snort call per batch.

WHY NOT STEP-BY-STEP RL
-----------------------
Measured: a Snort invocation costs 9.93 s for 1 packet and 11.8 s for 120k
packets, so ~9.9 s is rule loading regardless of input size.  A step-by-step
env therefore pays ~10 s per episode, and PPO additionally needs the reward at
the terminal step, which forces one call per episode (measured: 0-6 fps).

Because verdicts are only affordable in batches, the problem is better posed
as a BANDIT: one action = one complete mutation plan for one flow, one reward
= that plan's real Snort outcome.  A batch of B plans costs ONE call, so
throughput scales with B instead of being pinned to ~0.1 episodes/s.

This also fixes the deterministic collapse seen with the step-by-step policy
(37.5% stochastic / 0% argmax): the action here is a complete plan, so argmax
is well defined -- there is no per-step commitment to get wrong.

Reward:
    -alerts + EVASION_BONUS   if alerts == 0
    -alerts - COST * n_corrupt  otherwise

The small per-packet cost is deliberate: without it the optimal policy is
trivially "corrupt everything" (measured 100% evasion at k=8).  With it the
agent is pushed toward the MINIMAL set of packets that still evades, which is
the actually interesting question.

Usage:
    /tmp/jev-poc/venv/bin/python ai_agent/snort_bandit.py --flows 24 --rounds 8 --batch 96
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from real_packet_env import ACTION_MAX_PACKETS, RealPacketEnv  # noqa: E402

EVASION_BONUS = 10.0
CORRUPT_COST = 0.25
MAX_PKT_FEAT = 8


# ---------------------------------------------------------------------------
# packet-level plan application
# ---------------------------------------------------------------------------
def apply_corrupt_mask(packets: list, mask: np.ndarray) -> list:
    """Corrupt the payload start of every packet selected by ``mask``.

    Byte assignment (not a delta) is required: `(b + 1 + 127) % 256` applied
    twice restores the original byte, so a delta-based corruption silently
    UNDOES itself when a packet is hit twice (measured: k=4 -> 66.7% evasion,
    k=5 -> 0%).
    """
    from scapy.all import IP, Raw, TCP, UDP

    out = []
    for i, pkt in enumerate(packets):
        p = pkt.copy()
        if i < len(mask) and mask[i] > 0.5 and Raw in p:
            pl = bytearray(bytes(p[Raw].load))
            if pl:
                k = max(1, int(len(pl) * 0.5))
                for j in range(min(k, len(pl))):
                    pl[j] = (j * 97 + 13) % 256
                p[Raw].load = bytes(pl)
                if IP in p:
                    del p[IP].chksum
                if UDP in p:
                    del p[UDP].chksum
                elif TCP in p:
                    del p[TCP].chksum
        out.append(p)
    return out


def packet_features(packets: list) -> np.ndarray:
    """(max_packets, MAX_PKT_FEAT) per-packet features for the policy."""
    from scapy.all import IP, TCP, UDP

    n = len(packets)
    feats = np.zeros((ACTION_MAX_PACKETS, MAX_PKT_FEAT), dtype=np.float32)
    for i, p in enumerate(packets[:ACTION_MAX_PACKETS]):
        dsize = len(bytes(p[IP].payload)) if IP in p else 0
        raw = 0
        from scapy.all import Raw
        if Raw in p:
            raw = len(bytes(p[Raw].load))
        feats[i] = np.array([
            dsize / 1500.0,
            raw / 1500.0,
            1.0 if UDP in p else 0.0,
            1.0 if TCP in p else 0.0,
            i / max(n - 1, 1),
            1.0 if i == 0 else 0.0,
            1.0 if i == n - 1 else 0.0,
            1.0 if i < n else 0.0,
        ], dtype=np.float32)
    return feats


# ---------------------------------------------------------------------------
# policy: per-packet Bernoulli over "corrupt this packet"
# ---------------------------------------------------------------------------
class PacketPolicy(nn.Module):
    def __init__(self, hidden: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(MAX_PKT_FEAT, hidden), nn.Tanh(),
            nn.Linear(hidden, hidden), nn.Tanh(),
            nn.Linear(hidden, 1),
        )

    def logits(self, feats: torch.Tensor) -> torch.Tensor:
        """feats: (B, P, F) -> (B, P) logits."""
        return self.net(feats).squeeze(-1)

    def sample(self, feats: torch.Tensor):
        lg = self.logits(feats)
        dist = torch.distributions.Bernoulli(logits=lg)
        a = dist.sample()
        return a, dist.log_prob(a).sum(dim=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=24)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--batch", type=int, default=96)
    ap.add_argument("--lr", type=float, default=3e-3)
    ap.add_argument("--corrupt-cost", type=float, default=0.25,
                    help="per-packet cost. Must exceed EVASION_BONUS/32 = 0.3125 "
                         "to make 'corrupt everything' suboptimal; at 0.25 the "
                         "argmax simply corrupts all 32 packets.")
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--out", default=str(REPO / "snort_validation/reports/snort_bandit.json"))
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=args.flows, batch_size=args.batch,
                        capture=args.capture, max_mutations=12, seed=11)
    flows = env.flows
    n = len(flows)
    print(f"[*] {n} real positive flows from {args.capture}")

    # baseline verdicts (no mutation)
    base = env._svc.alert_counts_chunked(
        [(pkts, i) for i, (_k, pkts) in enumerate(flows)])
    print(f"[*] baseline detected: {sum(1 for v in base.values() if v > 0)}/{n}")

    # cache all packet features once
    feats_all = torch.tensor(
        np.stack([packet_features(pkts) for _k, pkts in flows]), dtype=torch.float32)

    torch.manual_seed(0)
    policy = PacketPolicy()
    opt = torch.optim.Adam(policy.parameters(), lr=args.lr)
    baseline = 0.0
    history = []

    for rnd in range(args.rounds):
        # --- sample a batch of (flow, mask) plans -------------------------
        idxs = np.random.default_rng(rnd).integers(0, n, size=args.batch)
        # Sample WITHOUT no_grad: REINFORCE needs log_prob to stay attached to
        # the parameters (only the sampled action itself is detached).
        feats = feats_all[idxs]
        lg = policy.logits(feats)
        dist = torch.distributions.Bernoulli(logits=lg)
        masks = dist.sample().detach()
        logps = dist.log_prob(masks).sum(dim=1)

        # --- ONE Snort call scores the whole batch ------------------------
        items = []
        for b, fi in enumerate(idxs):
            m = masks[b].numpy()
            pkts = apply_corrupt_mask(flows[fi][1], m)
            items.append((pkts, b))
        counts = env._svc.alert_counts_chunked(items)

        rewards = np.zeros(args.batch, dtype=np.float32)
        n_corrupt = masks.sum(dim=1).numpy()
        for b in range(args.batch):
            alerts = int(counts.get(b, 1))
            r = -float(alerts) - args.corrupt_cost * float(n_corrupt[b])
            if alerts == 0:
                r += EVASION_BONUS
            rewards[b] = r

        # --- REINFORCE with a moving-average baseline ---------------------
        adv = torch.tensor(rewards - baseline, dtype=torch.float32)
        loss = -(logps * adv).mean()
        opt.zero_grad()
        loss.backward()
        opt.step()
        baseline = 0.9 * baseline + 0.1 * float(rewards.mean())

        evaded = int(sum(1 for b in range(args.batch)
                         if int(counts.get(b, 1)) == 0))
        mean_corrupt_evaded = (
            float(n_corrupt[[b for b in range(args.batch)
                             if int(counts.get(b, 1)) == 0]].mean())
            if evaded else float("nan"))
        row = {"round": rnd, "evaded": evaded, "batch": args.batch,
               "evasion_pct": round(100 * evaded / args.batch, 1),
               "mean_reward": round(float(rewards.mean()), 3),
               "mean_corrupt_all": round(float(n_corrupt.mean()), 2),
               "mean_corrupt_when_evaded": (
                   None if np.isnan(mean_corrupt_evaded)
                   else round(mean_corrupt_evaded, 2))}
        history.append(row)
        print(f"[round {rnd}] evaded {evaded}/{args.batch} "
              f"({row['evasion_pct']}%)  mean_reward={row['mean_reward']}  "
              f"corrupt/plan={row['mean_corrupt_all']}  "
              f"corrupt|evaded={row['mean_corrupt_when_evaded']}")

    # --- deterministic evaluation (argmax mask) ---------------------------
    with torch.no_grad():
        lg = policy.logits(feats_all)
        det_masks = (lg > 0).float()
    items = []
    for fi, (_k, pkts) in enumerate(flows):
        items.append((apply_corrupt_mask(pkts, det_masks[fi].numpy()), fi))
    dc = env._svc.alert_counts_chunked(items)
    det_evaded = sum(1 for v in dc.values() if v == 0)
    det_corrupt = det_masks.sum(dim=1).numpy()
    print(f"\n[*] DETERMINISTIC (argmax): evaded {det_evaded}/{n} "
          f"({100*det_evaded/n:.1f}%)  mean_corrupt={det_corrupt.mean():.2f}")

    # random control
    rng = np.random.default_rng(3)
    items = []
    for fi, (_k, pkts) in enumerate(flows):
        m = (rng.random(ACTION_MAX_PACKETS) < 0.5).astype(np.float32)
        items.append((apply_corrupt_mask(pkts, m), fi))
    rc = env._svc.alert_counts_chunked(items)
    r_evaded = sum(1 for v in rc.values() if v == 0)
    print(f"[*] random control:        evaded {r_evaded}/{n} "
          f"({100*r_evaded/n:.1f}%)")

    # all-packets control
    items = []
    for fi, (_k, pkts) in enumerate(flows):
        m = np.ones(ACTION_MAX_PACKETS, dtype=np.float32)
        items.append((apply_corrupt_mask(pkts, m), fi))
    ac = env._svc.alert_counts_chunked(items)
    a_evaded = sum(1 for v in ac.values() if v == 0)
    print(f"[*] corrupt-all control:   evaded {a_evaded}/{n} "
          f"({100*a_evaded/n:.1f}%)")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({
            "capture": args.capture, "flows": n, "rounds": args.rounds,
            "batch": args.batch, "history": history,
            "deterministic_evaded": int(det_evaded),
            "deterministic_pct": round(100 * det_evaded / n, 2),
            "deterministic_mean_corrupt": round(float(det_corrupt.mean()), 2),
            "random_evaded": int(r_evaded),
            "random_pct": round(100 * r_evaded / n, 2),
            "corrupt_all_evaded": int(a_evaded),
            "corrupt_all_pct": round(100 * a_evaded / n, 2),
            "snort_stats": env.service_stats(),
        }, f, indent=2)
    print(f"[+] report: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
