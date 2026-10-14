"""Are the 3 UDP SIDs actually C2, or BitTorrent P2P policy rules?

The user's objection: DHT is peer-to-peer, not command-and-control.  If that
is right, then a large share of the "C2 corpus" is not C2 at all, and every
evasion number computed over those flows is measuring the wrong thing.

We check two independent things, because either alone is inconclusive:

  1. The rules' own metadata.  classtype/policy is the analyst's stated intent.
  2. The flows' own bytes.  A BitTorrent DHT KRPC message is bencode with a
     `t`/`y`/`a` envelope; a C2 check-in is a request to a server endpoint.
     We decode the bencode envelope and report what the traffic says it is,
     independent of what the rule claims.

The two disagreeing is the finding: rule intent is not evidence about traffic.
"""
import collections
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.packet import Raw  # noqa: E402

from hidden_defender_env import HiddenDefenderEnv, client_ip_of  # noqa: E402

RULES = ROOT / "snort_validation/et_open_c2/et_open_c2.rules"
UDP_SIDS = ["2008581", "2008583", "2008585"]
TCP_SIDS = ["2012533", "2012627", "2014635"]


def decode_bencode(data: bytes, pos: int = 0):
    """Minimal bencode reader.

    Returns (value, next_pos).  value is one of:
      dict[str, Any] | list[Any] | int | bytes | None
    Per BEP 3 a dict key is always a bencoded string, so keys decode to bytes;
    we surface them as str for readability.  None means "not valid bencode".
    """
    if pos >= len(data):
        return None, pos
    ch = data[pos:pos + 1]
    if ch == b"i":
        end = data.find(b"e", pos)
        if end < 0:
            return None, pos
        try:
            return int(data[pos + 1:end]), end + 1
        except ValueError:
            return None, pos
    if ch in (b"l", b"d"):
        is_dict = ch == b"d"
        pos += 1
        out_list: list = []
        out_dict: dict = {}
        while pos < len(data) and data[pos:pos + 1] != b"e":
            if is_dict:
                key, pos = decode_bencode(data, pos)
                if pos >= len(data):
                    return None, pos
                val, pos = decode_bencode(data, pos)
                if pos >= len(data):
                    return None, pos
                if not isinstance(key, bytes):
                    return None, pos
                out_dict[key.decode("latin1")] = val
            else:
                val, pos = decode_bencode(data, pos)
                if pos >= len(data):
                    return None, pos
                out_list.append(val)
        if pos >= len(data):
            return None, pos
        return (out_dict if is_dict else out_list), pos + 1
    if ch.isdigit():
        colon = data.find(b":", pos)
        if colon < 0:
            return None, pos
        try:
            ln = int(data[pos:colon])
        except ValueError:
            return None, pos
        end = colon + 1 + ln
        if end > len(data):
            return None, pos
        return data[colon + 1:end], end
    return None, pos


def main() -> None:
    print("=" * 74)
    print("1. RULE METADATA — analyst intent, straight from classtype/policy")
    print("=" * 74)
    lines = RULES.read_text(errors="ignore").splitlines()
    for sid in UDP_SIDS + TCP_SIDS:
        line = next((l for l in lines if f"sid:{sid};" in l), "")
        msg = re.search(r'msg:"([^"]*)"', line)
        cls = re.search(r'classtype:(\S+?);', line)
        pol = re.search(r'policy:([^;]*);', line)
        rev = re.search(r'rev:(\S+?);', line)
        proto = " ".join(line.split()[1:3])
        print(f"sid {sid} [{proto}] rev={rev.group(1) if rev else '?'}")
        print(f"    classtype: {cls.group(1) if cls else '?'}")
        print(f"    policy:    {pol.group(1).strip() if pol else '?'}")
        print(f"    msg:       {msg.group(1)[:78] if msg else '?'}")
    print()

    print("=" * 74)
    print("2. TRAFFIC — what the bytes say, decoded independently")
    print("=" * 74)
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    envelopes = collections.Counter()
    queries = collections.Counter()
    udp_ok = udp_bad = 0
    samples = []
    for flow in env._flows:
        pkts = list(flow["packets"])
        cid = client_ip_of(flow["flow_id"])
        for p in pkts:
            if UDP not in p or IP not in p or Raw not in p:
                continue
            if p[IP].src != cid:
                continue
            val, _ = decode_bencode(bytes(p[Raw].load))
            if isinstance(val, dict):
                udp_ok += 1
                y = val.get("y")
                t = val.get("t")
                q = (val.get("a") or {}).get("q") if isinstance(val.get("a"), dict) else None
                envelopes[y if isinstance(y, str) else type(y).__name__] += 1
                queries[q if isinstance(q, str) else type(q).__name__] += 1
                if len(samples) < 6:
                    shown = {k: (v if not isinstance(v, bytes) else v[:24])
                             for k, v in val.items()}
                    samples.append((flow["flow_id"], shown))
            else:
                udp_bad += 1
    print(f"UDP client packets that decode as a bencode dict: {udp_ok}")
    print(f"UDP client packets that do NOT:                   {udp_bad}")
    print(f"  'y' (KRPC message type) histogram: {dict(envelopes)}")
    print(f"  'q' (query verb) histogram:        {dict(queries)}")
    print()
    print("Sample decoded KRPC envelopes:")
    for fid, val in samples:
        keys = ",".join(sorted(str(k) for k in val))
        a = val.get("a")
        akeys = ",".join(sorted(str(k) for k in a)) if isinstance(a, dict) else "-"
        print(f"  {str(fid)[:20]:20s} y={val.get('y')!r:5s} t={val.get('t')!r:8s} "
              f"topkeys=[{keys}] a=[{akeys}]")

    print()
    print("=" * 74)
    print("3. VERDICT")
    print("=" * 74)
    policy_sids = [s for s in UDP_SIDS
                   if "policy-violation" in next((l for l in lines
                                                 if f"sid:{s};" in l), "")]
    print(f"UDP SIDs classtype policy-violation: {policy_sids}")
    if udp_ok and set(envelopes) <= {"q", "r", "e", "a", None}:
        print("Traffic decodes as BitTorrent KRPC (DHT) -- peer-to-peer discovery,")
        print("not a command-and-control session.")


if __name__ == "__main__":
    main()