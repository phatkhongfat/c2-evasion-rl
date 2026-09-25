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
the actually interesting question.  ``n_corrupt`` counts packets a plan
ACTUALLY corrupts (a mask slot with no payload is free) -- counting raw mask
bits charged flows for packets they do not have and made the cost sweep
incomparable across captures with different flow lengths.

THREE EXPERIMENTS, ONE CODE PATH
--------------------------------
``--sweep-cost``, ``--scale-flows`` and ``--captures`` are all loops around the
SAME ``run_bandit`` call.  Earlier versions shelled out to a per-experiment
script that re-parsed this file's stdout, which duplicated the argument set,
lost the JSON on any extra print, and let the experiments drift apart.

Usage:
    # single run
    python ai_agent/snort_bandit.py --flows 24 --rounds 8 --batch 96 --resident

    # corrupt-cost sweep on one capture
    python ai_agent/snort_bandit.py --flows 24 --rounds 8 --resident \
        --sweep-cost 0.2,0.4,0.6,0.8,1.0 --out reports/sweep_corrupt_cost.json

    # flow scale-up
    python ai_agent/snort_bandit.py --rounds 8 --resident --corrupt-cost 0.6 \
        --scale-flows 24,50,100,200 --out reports/scale_flows.json

    # cross-capture validation (one report per capture)
    python ai_agent/snort_bandit.py --flows 24 --rounds 8 --resident \
        --captures cap-a,cap-b --out-dir reports/cross_capture
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from real_packet_env import ACTION_MAX_PACKETS, RealPacketEnv  # noqa: E402
from control_gate import policy_beats_control  # noqa: E402,F401 - re-exported

EVASION_BONUS = 10.0

# Per-packet corruption cost.  A flow that evades nets
# ``EVASION_BONUS - cost * n_corrupted``, so corrupting MORE is only rational
# while that stays positive.  The old default (0.25) was derived against
# ``EVASION_BONUS / ACTION_MAX_PACKETS`` = 0.3125, i.e. it assumed every one of
# the 32 action slots held a corruptable payload packet.  They do not: on real
# captures only 0.6-10.5 packets per flow carry a payload, so the real
# break-even is ``EVASION_BONUS / n_corruptable`` = 0.95-3.45, not 0.3125.
# At 0.25 corrupting everything netted +3.70 .. +9.63, making the corrupt-all
# control the reward-optimal action and leaving the policy nothing to learn.
# See ``break_even_cost`` and tests/test_beats_control.py.
CORRUPT_COST = 1.0
MAX_PKT_FEAT = 8


def break_even_cost(n_corruptable: float) -> float:
    """Corruption cost at which corrupting every reachable packet breaks even.

    ``n_corruptable`` is how many packets in the flow can actually be mutated
    (payload present, index < ACTION_MAX_PACKETS) -- NOT the action-space width.
    Above this cost, evicting by blanket corruption nets less than doing
    nothing, so a sparse plan is the only reward-maximising choice.

    Returns ``inf`` for a flow with no reachable packet: nothing can be gained
    at any price, which keeps callers from dividing by zero.
    """
    if n_corruptable <= 0:
        return float("inf")
    return EVASION_BONUS / n_corruptable


def write_json_atomic(path, payload) -> None:
    """Write JSON via a temp file + rename, so a crash cannot leave a partial."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(path)


# ---------------------------------------------------------------------------
# packet-level plan application
# ---------------------------------------------------------------------------
def corrupt_targets(packets: list, mask: np.ndarray) -> list:
    """Indices of packets a mask actually corrupts (needs a payload).

    Single definition of "corrupted": the mutator and the cost accounting must
    agree, or the reported cost is not the cost that was paid.
    """
    from scapy.all import Raw

    return [i for i, pkt in enumerate(packets)
            if i < len(mask) and mask[i] > 0.5 and Raw in pkt]


def apply_corrupt_mask(packets: list, mask: np.ndarray) -> list:
    """Corrupt the payload start of every packet selected by ``mask``.

    Byte assignment (not a delta) is required: `(b + 1 + 127) % 256` applied
    twice restores the original byte, so a delta-based corruption silently
    UNDOES itself when a packet is hit twice (measured: k=4 -> 66.7% evasion,
    k=5 -> 0%).
    """
    from scapy.all import IP, Raw, TCP, UDP

    hit = set(corrupt_targets(packets, mask))
    out = []
    for i, pkt in enumerate(packets):
        p = pkt.copy()
        if i in hit:
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
    from scapy.all import IP, Raw, TCP, UDP

    n = len(packets)
    feats = np.zeros((ACTION_MAX_PACKETS, MAX_PKT_FEAT), dtype=np.float32)
    for i, p in enumerate(packets[:ACTION_MAX_PACKETS]):
        dsize = len(bytes(p[IP].payload)) if IP in p else 0
        raw = len(bytes(p[Raw].load)) if Raw in p else 0
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


def score(svc, items, label=""):
    """Alert counts with ONE retry, then skip (plan: handle Snort crashes)."""
    try:
        return svc.alert_counts_chunked(items)
    except Exception as exc:  # noqa: BLE001 - service may die mid-sweep
        print(f"[!] snort failed on {label} ({exc}); restarting and retrying")
        if hasattr(svc, "restart"):
            svc.restart()
        try:
            return svc.alert_counts_chunked(items)
        except Exception as exc2:  # noqa: BLE001
            print(f"[!] snort failed again on {label} ({exc2}); skipping")
            return {q: 1 for _p, q in items}   # assume detected, never "evaded"


def control_evasion(svc, flows, mask_fn, label):
    """Score one control policy over every flow. Returns (evaded, mean_corrupt)."""
    masks = [mask_fn(pkts) for _k, pkts in flows]
    items = [(apply_corrupt_mask(pkts, m), i)
             for i, ((_k, pkts), m) in enumerate(zip(flows, masks))]
    counts = score(svc, items, label)
    evaded = sum(1 for v in counts.values() if v == 0)
    n_corrupt = [len(corrupt_targets(pkts, m))
                 for (_k, pkts), m in zip(flows, masks)]
    return evaded, float(np.mean(n_corrupt)), masks


def run_bandit(flows, svc, *, capture, rounds, batch, corrupt_cost,
               lr=3e-3, seed=0, verbose=True) -> dict:
    """Train + evaluate ONE bandit configuration against real Snort.

    ``flows`` is the env's flow list, so several configs can share one flow set
    (the corrupt-cost sweep must compare costs on IDENTICAL flows).
    """
    n = len(flows)
    feats_all = torch.tensor(
        np.stack([packet_features(pkts) for _k, pkts in flows]),
        dtype=torch.float32)

    # Baseline: unmutated flows must be DETECTED, or "evasion" is vacuous.
    base = score(svc, [(pkts, i) for i, (_k, pkts) in enumerate(flows)],
                 f"{capture} baseline")
    base_det = sum(1 for v in base.values() if v > 0)

    torch.manual_seed(seed)
    policy = PacketPolicy()
    opt = torch.optim.Adam(policy.parameters(), lr=lr)
    baseline = 0.0
    history = []

    for rnd in range(rounds):
        # --- sample a batch of (flow, mask) plans -------------------------
        idxs = np.random.default_rng(seed + rnd).integers(0, n, size=batch)
        # Sample WITHOUT no_grad: REINFORCE needs log_prob to stay attached to
        # the parameters (only the sampled action itself is detached).
        feats = feats_all[idxs]
        lg = policy.logits(feats)
        dist = torch.distributions.Bernoulli(logits=lg)
        masks = dist.sample().detach()
        logps = dist.log_prob(masks).sum(dim=1)

        # --- ONE Snort call scores the whole batch ------------------------
        items, n_corrupt = [], np.zeros(batch, dtype=np.float32)
        for b, fi in enumerate(idxs):
            m = masks[b].numpy()
            pkts = flows[fi][1]
            n_corrupt[b] = len(corrupt_targets(pkts, m))
            items.append((apply_corrupt_mask(pkts, m), b))
        counts = score(svc, items, f"{capture} round {rnd}")

        rewards = np.zeros(batch, dtype=np.float32)
        for b in range(batch):
            alerts = int(counts.get(b, 1))
            r = -float(alerts) - corrupt_cost * float(n_corrupt[b])
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

        evaded_idx = [b for b in range(batch) if int(counts.get(b, 1)) == 0]
        evaded = len(evaded_idx)
        row = {"round": rnd, "evaded": evaded, "batch": batch,
               "evasion_pct": round(100 * evaded / batch, 1),
               "mean_reward": round(float(rewards.mean()), 3),
               "mean_corrupt_all": round(float(n_corrupt.mean()), 2),
               "mean_corrupt_when_evaded": (
                   round(float(n_corrupt[evaded_idx].mean()), 2)
                   if evaded else None)}
        history.append(row)
        if verbose:
            print(f"[round {rnd}] evaded {evaded}/{batch} "
                  f"({row['evasion_pct']}%)  mean_reward={row['mean_reward']}  "
                  f"corrupt/plan={row['mean_corrupt_all']}  "
                  f"corrupt|evaded={row['mean_corrupt_when_evaded']}")

    # --- deterministic evaluation (argmax mask) ---------------------------
    with torch.no_grad():
        lg = policy.logits(feats_all)
        det_masks = (lg > 0).float()
    items = [(apply_corrupt_mask(pkts, det_masks[fi].numpy()), fi)
             for fi, (_k, pkts) in enumerate(flows)]
    dc = score(svc, items, f"{capture} argmax")
    det_evaded = sum(1 for v in dc.values() if v == 0)
    det_corrupt = [len(corrupt_targets(pkts, det_masks[fi].numpy()))
                   for fi, (_k, pkts) in enumerate(flows)]

    # --- controls: random plan, and corrupt-everything --------------------
    rng = np.random.default_rng(seed + 3)
    r_evaded, r_corrupt, _ = control_evasion(
        svc, flows, lambda _p: (rng.random(ACTION_MAX_PACKETS) < 0.5)
        .astype(np.float32), f"{capture} random")
    a_evaded, a_corrupt, _ = control_evasion(
        svc, flows, lambda _p: np.ones(ACTION_MAX_PACKETS, dtype=np.float32),
        f"{capture} corrupt-all")

    if verbose:
        print(f"[*] baseline detected:  {base_det}/{n}")
        print(f"[*] DETERMINISTIC (argmax): evaded {det_evaded}/{n} "
              f"({100*det_evaded/n:.1f}%)  "
              f"mean_corrupt={float(np.mean(det_corrupt)):.2f}")
        print(f"[*] random control:        evaded {r_evaded}/{n} "
              f"({100*r_evaded/n:.1f}%)")
        print(f"[*] corrupt-all control:   evaded {a_evaded}/{n} "
              f"({100*a_evaded/n:.1f}%)")

    return {
        "capture": capture, "flows": n, "rounds": rounds, "batch": batch,
        "corrupt_cost": corrupt_cost,
        "baseline_detected": int(base_det),
        "history": history,
        "deterministic_evaded": int(det_evaded),
        "deterministic_pct": round(100 * det_evaded / n, 2),
        "deterministic_mean_corrupt": round(float(np.mean(det_corrupt)), 2),
        "random_evaded": int(r_evaded),
        "random_pct": round(100 * r_evaded / n, 2),
        "random_mean_corrupt": round(r_corrupt, 2),
        "corrupt_all_evaded": int(a_evaded),
        "corrupt_all_pct": round(100 * a_evaded / n, 2),
        "corrupt_all_mean_corrupt": round(a_corrupt, 2),
    }


def load_env(capture, n_flows, batch, dataset, seed=11):
    """Build a RealPacketEnv; ``n_flows='auto'`` loads every usable flow."""
    if n_flows != "auto":
        n_flows = int(n_flows)   # argparse hands --flows over as a string
    env = RealPacketEnv(n_flows=None if n_flows == "auto" else n_flows,
                        batch_size=batch, capture=capture, max_mutations=12,
                        seed=seed, dataset=dataset)
    return env, env.flows, len(env.flows)


def run_configs(configs, get_svc, resident, args, out_dir=None, verbose=True):
    """Run every ``(capture, n_flows, corrupt_cost)`` config, in order.

    ONE loop for sweep / scale / cross-capture.  The three experiments differ
    only in which field varies, so three loops meant three copies of
    load-env / run / collect, and the per-experiment wrapper scripts that used
    to hold those copies had to re-parse this file's stdout to get the numbers
    back.  Envs are cached because the corrupt-cost sweep must compare costs on
    IDENTICAL flows, and re-loading a pcap per cost would both change the flow
    set and pay the pcap scan again.

    A config whose capture cannot supply the requested number of flows is
    SKIPPED, not run: a pool shortfall means the requested measurement is not
    available, and quietly sampling 24 plans from a 1-flow pool produces a
    number that looks like a result and is not one.
    """
    svc = get_svc()
    env_cache, rows, skipped = {}, [], []
    for capture, n_flows, cost in configs:
        key = (capture, n_flows)
        if key not in env_cache:
            env_cache[key] = load_env(capture, n_flows, args.batch, args.dataset)
        _env, flows, n = env_cache[key]
        if n_flows != "auto" and n < int(n_flows):
            msg = (f"{capture}: pool has {n} usable flows, {n_flows} requested")
            print(f"[!] SKIP {msg}")
            skipped.append({"capture": capture, "requested": int(n_flows),
                            "available": n, "reason": "pool_shortfall"})
            continue
        if verbose:
            print(f"\n=== {capture} | n_flows={n} | corrupt_cost={cost} ===")
        r = run_bandit(flows, svc, capture=capture, rounds=args.rounds,
                       batch=args.batch, corrupt_cost=cost, lr=args.lr,
                       seed=args.seed)
        row = {"capture": capture, "dataset": args.dataset, "n_flows": n,
               "corrupt_cost": cost,
               "deterministic_evaded": r["deterministic_evaded"],
               "evasion_pct": r["deterministic_pct"],
               "mean_corrupt": r["deterministic_mean_corrupt"],
               "baseline_detected": r["baseline_detected"],
               "random_evaded": r["random_evaded"],
               "corrupt_all_evaded": r["corrupt_all_evaded"],
               "corrupt_all_mean_corrupt": r["corrupt_all_mean_corrupt"],
               "history": r["history"]}
        rows.append(row)
        if out_dir is not None:
            r["dataset"] = args.dataset
            r["snort_stats"] = svc.stats() if resident else None
            write_json_atomic(out_dir / f"cross_capture_{capture}.json", r)
            print(f"[+] report: {out_dir}/cross_capture_{capture}.json")
    return svc, rows, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", default="24",
                    help="flow count, or 'auto' for every usable flow")
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--batch", type=int, default=96)
    ap.add_argument("--lr", type=float, default=3e-3)
    ap.add_argument("--corrupt-cost", type=float, default=CORRUPT_COST,
                    help="per-packet cost. For a flow with N reachable "
                         "payload packets, 'corrupt everything' nets "
                         "EVASION_BONUS - cost*N, so the cost must exceed "
                         "break_even_cost(N) = EVASION_BONUS/N to make a "
                         "sparse plan preferable. Measured N is 0.6-10.5 per "
                         "flow, i.e. break-even 0.95-3.45 -- not the 0.3125 "
                         "you get from the 32-wide action space.")
    ap.add_argument("--sweep-cost", default=None,
                    help="comma list of costs; one run per cost on ONE flow set")
    ap.add_argument("--scale-flows", default=None,
                    help="comma list of flow counts; one run per count")
    ap.add_argument("--captures", default=None,
                    help="comma list of captures; one report per capture")
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--dataset", default="ctu13",
                    choices=["ctu13", "stratosphere"])
    ap.add_argument("--resident", action="store_true",
                    help="use the resident Snort service (IDS on lo) instead of "
                         "one process per batch; removes the ~9.9s rule-load "
                         "floor per batch")
    ap.add_argument("--out",
                    default=str(REPO / "snort_validation/reports/snort_bandit.json"))
    ap.add_argument("--out-dir", default=None,
                    help="with --captures: write cross_capture_<name>.json here")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    resident = None
    svc = None
    if args.resident:
        from snort_resident_service import ResidentSnortService
        resident = ResidentSnortService()
        if not resident.start():
            print(f"[!] resident snort unavailable ({resident.error}); "
                  f"falling back to per-batch service")
            resident = None
        else:
            svc = resident
            print("[*] using RESIDENT snort (no per-batch rule reload)")

    def get_svc():
        """The scoring service: resident if available, else per-batch."""
        if svc is not None:
            return svc
        from snort_batch_service import SnortBatchService
        return SnortBatchService(batch_size=args.batch)

    # mode -> (configs, out_dir); exactly one mode may be selected
    if args.sweep_cost:
        costs = [float(c) for c in args.sweep_cost.split(",")]
        configs = [(args.capture, args.flows, c) for c in costs]
        mode, out_dir = "sweep", None
    elif args.scale_flows:
        configs = [(args.capture, int(n), args.corrupt_cost)
                   for n in args.scale_flows.split(",")]
        mode, out_dir = "scale", None
    elif args.captures:
        caps = [c.strip() for c in args.captures.split(",") if c.strip()]
        configs = [(c, args.flows, args.corrupt_cost) for c in caps]
        mode, out_dir = "cross", Path(args.out_dir or Path(args.out).parent)
    else:
        configs = [(args.capture, args.flows, args.corrupt_cost)]
        mode, out_dir = "single", None

    try:
        svc, rows, skipped = run_configs(configs, get_svc, resident, args, out_dir)
        if not rows:
            print("[-] no config produced a measurement", file=sys.stderr)
            return 1
        if mode == "cross":
            return 0
        payload = {
            "dataset": args.dataset, "capture": args.capture,
            "rounds": args.rounds, "batch": args.batch,
            "skipped": skipped,
            "snort_stats": svc.stats() if resident else None,
        }
        if mode == "sweep":
            payload["flows"] = rows[0]["n_flows"]
            payload["sweep_results"] = rows
        elif mode == "scale":
            payload["corrupt_cost"] = args.corrupt_cost
            payload["scale_results"] = rows
        else:
            payload.update(rows[0])
            payload.pop("capture")
            payload["capture"] = args.capture
        write_json_atomic(args.out, payload)
        print(f"[+] report: {args.out}")
    finally:
        if resident is not None:
            resident.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
