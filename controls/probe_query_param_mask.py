"""Why is query_param_prepend masked off on every flow?

The mask clears index 16 unless an owned payload contains '?'.  That is the
guard, but it is a GUESS about the corpus: it says the CTU-13 HTTP requests
have no query string.  This probe measures the claim instead of inheriting it,
and distinguishes the two possible causes:

  (a) the framing is not "http"  -> masked at line 664 (protocol gate)
  (b) the framing is "http" but no owned payload contains '?' -> masked at 681

Then it asks the follow-up that decides whether the action can ever be worth
anything: on the flows that DO pass, does the mutation change any byte, and
does it still preserve semantics under the reward's own D8 gate?
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP  # noqa: E402
from scapy.packet import Raw  # noqa: E402

from c2_semantics import semantics_ok_reward  # noqa: E402
from endpoint_model import is_http_request  # noqa: E402
from hidden_defender_env import (  # noqa: E402
    HiddenDefenderEnv,
    apply_mech,
    client_ip_of,
)


def main() -> None:
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    print(f"{'flow_id':22s} {'framing':9s} {'m16':>4s} {'?':>3s} {'HTTP?':>6s} "
          f"{'reqline':>34s} {'chg':>4s} {'D8ok':>5s}")
    cause_a = cause_b = passes = 0
    changed_ok = 0
    for flow in env._flows:
        pkts = list(flow["packets"])
        cid = flow["flow_id"]
        owned = env._owned_payloads(flow)
        m16 = env._compute_action_mask()[16]
        has_q = any(b"?" in p for p in owned)
        http = any(
            Raw in p and is_http_request(bytes(p[Raw].load))
            for p in pkts if IP in p and p[IP].src == cid
        )
        framing = flow.get("framing", "unknown")
        # first request line, for eyeballing whether a query string exists
        req = b""
        for p in owned:
            if b" " in p[:64] and p.startswith((b"GET", b"POST", b"HEAD")):
                req = p.split(b"\r\n")[0]
                break
        chg = d8 = None
        if m16:
            passes += 1
            out = apply_mech(pkts, "query_param_prepend", client_ip=cid)
            chg = bytes(out[0][Raw].load) != bytes(pkts[0][Raw].load) if Raw in out[0] else None
            d8 = semantics_ok_reward(pkts, out, cid)
            if chg and d8:
                changed_ok += 1
        if not m16:
            if framing != "http":
                cause_a += 1
            else:
                cause_b += 1
        print(f"{str(cid)[:22]:22s} {framing:9s} {m16:>4d} {str(has_q):>5s} "
              f"{str(http):>6s} {req.decode('latin1')[:34]:>34s} "
              f"{str(chg):>4s} {str(d8):>5s}")

    n = len(env._flows)
    print()
    print(f"Tổng flow: {n}")
    print(f"  (a) masked do framing != 'http' (cổng protocol, dòng 664): {cause_a}")
    print(f"  (b) masked do framing == 'http' nhưng không có '?' (dòng 681): {cause_b}")
    print(f"  qua được mask: {passes}")
    print(f"  trong đó: mutation đổi byte VÀ giữ D8: {changed_ok}")


if __name__ == "__main__":
    main()