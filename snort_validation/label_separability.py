"""Can the policy's existing features identify the oracle packet?

This is the feasibility gate for behaviour cloning. If no rule over the current
8 per-packet features can pick a valid packet, cloning the oracle teaches noise.

Two measurements:
  1. single-feature rules  - argmax/argmin of each feature over the flow's
     payload packets; report how often the pick is a valid packet.
  2. an MLP on the same features, trained on a train split of FLOWS and scored
     on held-out flows. Top-1 accuracy is the number that matters, because
     evaluation takes the argmax mask.
"""
import sys
import json
import argparse
import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, "ai_agent")
from snort_bandit import packet_features, ACTION_MAX_PACKETS, MAX_PKT_FEAT
from real_packet_env import RealPacketEnv

FEATURE_NAMES = ["dsize/1500", "raw/1500", "is_udp", "is_tcp",
                 "i/(n-1)", "is_first", "is_last", "DEAD(i<n)"]


def build_xy(flows, labels):
    """-> list of (feats (P,F), valid_idx list) for flows that have a label."""
    out = []
    for fi, (_k, pk) in enumerate(flows):
        key = str(fi)
        if key not in labels["valid_single_packets"]:
            continue
        valid = labels["valid_single_packets"][key]
        out.append((packet_features(pk), sorted(valid)))
    return out


def single_feature_report(data):
    n_feat = MAX_PKT_FEAT
    print("\n--- single-feature rules (top-1 accuracy over payload packets) ---")
    print(f"{'feature':<14}{'argmax':>10}{'argmin':>10}")
    for f in range(n_feat):
        hit_hi = hit_lo = tot = 0
        for feats, valid in data:
            n = int((feats[:, 3] > 0).sum())  # reachable packet count
            idx = [i for i in range(ACTION_MAX_PACKETS) if i < n]
            col = feats[idx, f]
            tot += 1
            if idx[int(np.argmax(col))] in valid:
                hit_hi += 1
            if idx[int(np.argmin(col))] in valid:
                hit_lo += 1
        tag = FEATURE_NAMES[f] if f < len(FEATURE_NAMES) else f"f{f}"
        print(f"{tag:<14}{hit_hi/tot:>9.1%}{hit_lo/tot:>10.1%}   (n={tot})")


def mlp_report(data, seed=0, epochs=400):
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(data))
    cut = int(0.75 * len(data))
    tr = [data[i] for i in order[:cut]]
    te = [data[i] for i in order[cut:]]

    Xtr = torch.tensor(np.stack([d[0] for d in tr]), dtype=torch.float32)
    Ytr = torch.zeros((len(tr), ACTION_MAX_PACKETS), dtype=torch.float32)
    for i, (_f, valid) in enumerate(tr):
        for j in valid:
            Ytr[i, j] = 1.0
    w = Ytr.sum(1, keepdim=True)
    Ytr = Ytr / torch.clamp(w, min=1.0)      # equal weight to every valid packet

    net = nn.Sequential(nn.Linear(MAX_PKT_FEAT, 64), nn.Tanh(),
                        nn.Linear(64, 64), nn.Tanh(), nn.Linear(64, 1))
    opt = torch.optim.Adam(net.parameters(), lr=1e-2)
    for _ in range(epochs):
        opt.zero_grad()
        lg = net(Xtr).squeeze(-1)
        loss = nn.functional.binary_cross_entropy_with_logits(
            lg, Ytr, weight=(Ytr > 0).float() * 10.0 + 1.0)
        loss.backward()
        opt.step()

    def top1_hit(dset):
        hit = 0
        with torch.no_grad():
            for feats, valid in dset:
                lg = net(torch.tensor(feats, dtype=torch.float32).unsqueeze(0)).squeeze(0)
                n = int((feats[:, 3] > 0).sum())
                pick = int(torch.argmax(lg[:n]).item())
                hit += pick in valid
        return hit / len(dset)

    print("\n--- MLP on the same 8 features ---")
    print(f"train flows: {len(tr)}   held-out flows: {len(te)}")
    print(f"top-1 accuracy  train      : {top1_hit(tr):.1%}")
    print(f"top-1 accuracy  held-out   : {top1_hit(te):.1%}")
    print(f"chance level                : {np.mean([1/max(len(d[0])-int((d[0][:,3]==0).sum()),1) for d in te]):.1%}")
    return net


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--capture", required=True)
    a = ap.parse_args()

    labels = json.load(open(a.labels))
    flows = RealPacketEnv(n_flows=labels["n_flows"], capture=a.capture,
                          dataset=a.dataset, batch_size=64).flows
    data = build_xy(flows, labels)
    print(f"capture={a.capture}  labelled flows={len(data)}  "
          f"unevadable={labels['unevadable']}")
    if not data:
        print("no labelled flows")
        return 1
    single_feature_report(data)
    mlp_report(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
