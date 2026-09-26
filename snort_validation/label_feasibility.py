"""Feasibility gate: can the policy's features reproduce the optimal masks?

The frontier solver gives, per flow, the exact packet set that evades it with
the fewest corruptions. If a network over the CURRENT per-packet features
cannot hit those masks, behaviour cloning is pointless and the features are
what must change first.

Measures two things on held-out flows:
  * best single-feature rule (argmax / argmin of each feature)
  * an MLP trained with BCE on the optimal mask
Scoring is "mask equals the optimal mask" -- the strict bar, because the
deterministic evaluator corrupts exactly the slots with a positive logit.
"""
import json
import os
import sys

import numpy as np
import torch
import torch.nn as nn
from scapy.all import Raw

sys.path.insert(0, "ai_agent")
from real_packet_env import RealPacketEnv, ACTION_MAX_PACKETS   # noqa: E402
from snort_bandit import packet_features, MAX_PKT_FEAT       # noqa: E402
sys.path.insert(0, "snort_validation")
from control_gate import policy_beats_control                   # noqa: E402

CAPTURES = [("stratosphere", "botnet-capture-20110811-neris"),
            ("ctu13", "botnet-capture-20110819-bot")]


def load(ds, cap):
    lab = json.load(open(f"labels/oracle_{cap}.json"))
    flows = RealPacketEnv(n_flows=24, capture=cap, dataset=ds,
                          batch_size=64).flows
    X, Y, idx = [], [], []
    for fi_str, mask in lab["optimal_mask"].items():
        fi = int(fi_str)
        pk = flows[fi][1]
        pay = [i for i, p in enumerate(pk) if Raw in p and i < ACTION_MAX_PACKETS]
        f = packet_features(pk)                 # (32, MAX_PKT_FEAT)
        y = np.zeros(ACTION_MAX_PACKETS, dtype=np.float32)
        for j in mask:
            y[j] = 1.0
        X.append(f)
        Y.append(y)
        idx.append(fi)
    return np.stack(X), np.stack(Y), np.array(idx), lab


def main():
    torch.manual_seed(0)
    for ds, cap in CAPTURES:
        X, Y, idx, lab = load(ds, cap)
        n = len(X)
        rng = np.random.RandomState(0)
        perm = rng.permutation(n)
        cut = int(n * 0.75)
        tr, te = perm[:cut], perm[cut:]

        # --- best single-feature rule, fit on train, scored on test ---
        best = []
        for d in range(MAX_PKT_FEAT):
            for sgn in (1, -1):
                pick = sgn * X[tr, :, d].argmax(axis=1)
                hit = np.mean([(Y[tr][t][pick[t]] > 0) for t in range(len(tr))])
                best.append((hit, d, sgn))
        best.sort(reverse=True)
        top_hit, top_d, top_sgn = best[0]
        pick = top_sgn * X[te, :, top_d].argmax(axis=1)
        te_rule = np.mean([(Y[te][t][pick[t]] > 0) for t in range(len(te))])

        # --- MLP trained with BCE toward the optimal mask ---
        # Per-packet scoring: the same small net is applied to every slot, so
        # input is (flows, slots, feats) and output is (flows, slots).
        net = nn.Sequential(nn.Linear(MAX_PKT_FEAT, 32), nn.Tanh(),
                            nn.Linear(32, 1))
        opt = torch.optim.Adam(net.parameters(), lr=0.02)
        Xt = torch.tensor(X)
        Yt = torch.tensor(Y)
        for _ in range(3000):
            opt.zero_grad()
            loss = nn.functional.binary_cross_entropy_with_logits(
                net(Xt[tr]).squeeze(-1), Yt[tr])
            loss.backward()
            opt.step()
        with torch.no_grad():
            sel = (net(Xt[te]).squeeze(-1) > 0).float().numpy()
        exact = float(np.mean([np.array_equal(sel[t], Y[te][t])
                               for t in range(len(te))]))
        miss = [int(idx[te][t]) for t in range(len(te))
                if not np.array_equal(sel[t], Y[te][t])]

        print(f"\n=== {cap} ===")
        print(f"  flows with labels      : {n} (train {len(tr)} / test {len(te)})")
        print(f"  optimal corruptions    : mean {Y.sum(axis=1).mean():.2f}")
        print(f"  best single-feature    : train {top_hit:.0%}, "
              f"test {te_rule:.0%}  (feature {top_d}, sign {top_sgn:+d})")
        top5, seen_d = [], set()
        for hit, d, sgn in best:            # best is sorted desc by train hit
            if d in seen_d:
                continue
            seen_d.add(d)
            top5.append(f"f{d}{sgn:+d}={hit:.0%}")
            if len(top5) == 5:
                break
        print(f"  per-feature (train top5): {', '.join(top5)}")
        print(f"  MLP exact mask match   : test {exact:.0%}  missed flows {miss}")
        print(f"  control for comparison : {lab['control_mean_corrupt']:.2f} "
              f"corruptions, {lab['control_evaded']}/{lab['n_flows']} evaded")

        end_to_end(ds, cap, X, Y, idx, tr, net, lab)


def end_to_end(ds, cap, X, Y, idx, tr, net, lab):
    """Play the cloned policy's masks through real Snort and grade vs control.

    Matching the oracle mask exactly is not required -- what matters is whether
    the predicted mask still evades, and how many corruptions it spends.
    """
    from snort_resident_service import ResidentSnortService
    from snort_bandit import apply_corrupt_mask, score, ACTION_MAX_PACKETS
    flows = RealPacketEnv(n_flows=24, capture=cap, dataset=ds,
                          batch_size=64).flows
    Xt = torch.tensor(X)
    with torch.no_grad():
        sel = (net(Xt).squeeze(-1) > 0).float().numpy()
    masks = {int(idx[t]): sel[t] for t in range(len(idx))}

    svc = ResidentSnortService()
    if not svc.start():
        print("  END-TO-END: SNORT UNAVAILABLE:", svc.error)
        return
    try:
        items, ids = [], []
        for fi in range(len(flows)):
            m = masks.get(fi)
            if m is None:                     # unevadable flow: nothing to do
                continue
            items.append(apply_corrupt_mask(flows[fi][1], m))
            ids.append(fi)
        res = score(svc, list(zip(items, ids)), "clone")
        ev = [i for i, v in res.items() if v == 0]
        nc = float(np.mean([masks[i].sum() for i in masks]))
        # Use the control numbers from the solver's clean-instance run. A SECOND
        # batch on an already-used service instance is not comparable: measured
        # that way, flow 15 on 20110819-bot flipped to "evaded", while five
        # fresh instances all reported it detected (harness_variance.py).
        ca_ev = lab["control_evaded"]
        ca_nc = lab["control_mean_corrupt"]
        print(f"  END-TO-END cloned policy: {len(ev)}/{len(flows)} evaded "
              f"@ mean_corrupt={nc:.2f}")
        print(f"  END-TO-END control      : {ca_ev}/{len(flows)} evaded "
              f"@ mean_corrupt={ca_nc:.2f}")
        gate = policy_beats_control(
            policy_evaded=len(ev), n_flows=len(flows), policy_mean_corrupt=nc,
            control_mean_corrupt=ca_nc, control_evaded=ca_ev)
        print(f"  VERDICT: {gate['verdict']}  (beats={gate['beats']})")
    finally:
        svc.stop()


if __name__ == "__main__":
    main()
