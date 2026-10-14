"""Which flows can each ACTION family even reach?

Every existing mechanism only touches one protocol shape:
  - http_header_pad / http_header_case / length_wrapper / query_param_prepend
    -> TCP+HTTP only (guarded by is_http_request)
  - split* / prepend* / pad16 / corrupt8 / reorder / overlap8 / ttl
    -> transport-agnostic, but see the semantics gate
  - split_slow, prepend*, ttl, pad16, corrupt8, reorder  -> nothing at all
    on a non-HTTP flow, because they rewrite bytes the semantics gate rejects.

This probe measures the DENOMINATOR: how many test flows are HTTP vs DHT,
so we know whether a mechanism family has anything to act on.
"""
import collections
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP, UDP, TCP  # noqa: E402
from scapy.packet import Raw  # noqa: E402

from endpoint_model import is_http_request  # noqa: E402
from hidden_defender_env import HiddenDefenderEnv, client_ip_of  # noqa: E402


def main() -> None:
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    shapes = collections.Counter()
    per_flow = []
    for flow in env._flows:
        pkts = list(flow["packets"])
        cid = client_ip_of(flow["flow_id"])
        own = [p for p in pkts if IP in p and p[IP].src == cid]
        if any(TCP in p for p in own):
            transport = "TCP"
        elif any(UDP in p for p in own):
            transport = "UDP"
        else:
            transport = "?"
        http = any(
            Raw in p and is_http_request(bytes(p[Raw].load)) for p in own
        )
        capture = str(flow["flow_id"])[:22]
        shapes[(transport, http)] += 1
        per_flow.append((capture, transport, http))

    print(f"{'capture':24s} {'transport':10s} {'http?':6s}")
    for capture, transport, http in per_flow:
        print(f"{capture:24s} {transport:10s} {str(http):6s}")

    print()
    print("Tổng hợp (transport, is_http_request):")
    for key, count in sorted(shapes.items(), key=lambda kv: -kv[1]):
        print(f"  {key} -> {count}")

    n = len(per_flow)
    n_http = sum(1 for (_, _, h) in per_flow if h)
    n_udp = sum(1 for (_, t, _) in per_flow if t == "UDP")
    print()
    print(f"Tổng flow: {n}")
    print(f"HTTP (mọi action http-* chỉ chạm được): {n_http} ({n_http / n:.1%})")
    print(f"UDP/DHT (sid 2008581/3/5, không action http-* nào chạm được): {n_udp}")


if __name__ == "__main__":
    main()