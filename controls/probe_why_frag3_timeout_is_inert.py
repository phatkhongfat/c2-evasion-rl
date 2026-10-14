"""Why does frag3_timeout=60 still catch every split_slow flow?"""
import collections
import pathlib
import sys

ROOT = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.all import IP, Raw  # noqa: E402

from hidden_defender_env import apply_mech, client_ip_of, load_corpus  # noqa: E402
from real_rules_replica import (  # noqa: E402
    RealRulesReplica, _payloads, _reassembled_buffers,
)

f = next(x for x in load_corpus("test")
         if str(x["flow_id"]).find("neris") != -1)
rep = f["replica"]
cid = client_ip_of(f["flow_id"])
cand = apply_mech(list(f["packets"]), "split_slow", cid, ownership="client")

print(f"flow       : {f['flow_id']}")
print(f"proto      : {f.get('proto')}")
print(f"packets    : {len(f['packets'])} -> {len(cand)}")
print()

hdr = "  idx ip_id fragoff  mf  nbytes   time      payload[:24]"
print(hdr)
for i, p in enumerate(cand[:12]):
    ip = p[IP]
    n = len(bytes(p[Raw].load)) if Raw in p else 0
    head = bytes(p[Raw].load)[:24] if Raw in p else b""
    print(f"  {i:>3} {ip.id:>5} {ip.frag & 0x1FFF:>7} {str(bool(ip.flags)):>5}"
          f" {n:>7} {float(getattr(p, 'time', 0) or 0):>10.2f}"
          f"   {head!r}")
print()

groups = collections.defaultdict(list)
for p in cand:
    if IP not in p:
        continue
    ip = p[IP]
    off = (ip.frag & 0x1FFF) * 8
    mf = bool(ip.flags)
    if not mf and off == 0:
        continue
    groups[(ip.src, ip.dst, ip.proto, ip.id)].append((off, float(p.time), n))
print(f"defrag groups: {len(groups)}")
for k, v in list(groups.items())[:4]:
    ts = sorted(t for _, t, _ in v)
    gaps = [round(b - a, 1) for a, b in zip(ts, ts[1:])]
    print(f"  id={k[3]} frags={len(v)} gaps={gaps}")
print()

leaky = RealRulesReplica(rep.rules, reassemble=True, frag3_timeout=60.0)
blind = RealRulesReplica(rep.rules, reassemble=True)
print(f"verdict blind={blind.verdict(cand, home_ip=None)} "
      f"leaky={leaky.verdict(cand, home_ip=None)}")

for name, rep in (("blind", blind), ("leaky", leaky)):
    hits = rep.firing_rules(cand, home_ip=None)
    print(f"\n{name}: {len(hits)} rule(s) fired")
    handshake, fwd, both = rep._arms(cand, home_ip=None)
    rev = rep._reverse_arm(cand, both, None)
    for r in hits:
        arm = rep._payloads_for(r, fwd, both, rev, None)
        which = "fwd" if arm is fwd else ("both" if arm is both else "rev")
        print(f"  sid={r.sid} msg={r.msg!r} arm={which} n_buf={len(arm)}")
        for i, b in enumerate(arm):
            if r.fires([b], handshake):
                print(f"    matched buffer[{i}] len={len(b)} "
                      f"head={b[:60]!r}")
print(f"max payload len  blind={max((len(x) for x in _payloads(cand, False, None)), default=0)}")
print(f"reassembled buf len blind={max((len(x) for x in _reassembled_buffers(cand, False, None)), default=0)}")
print(f"reassembled buf len leaky={max((len(x) for x in _reassembled_buffers(cand, False, None, frag3_timeout=60.0)), default=0)}")