"""alert_counts_chunked must not depend on the caller's id values.

The resident service encodes the caller's ``qid`` straight onto the wire as
``uid = uid_base + qid`` and then reads verdicts back with ``qid = uid - uid_base``.
But ``_uid_to_addr_port`` only keeps ``hi = (uid // UID_PER_NET) % 250``, so a
large ``qid`` wraps the encoded address while the decode path does not. The
recovered id no longer matches, the counter is never incremented, and the flow
is reported as ``0 alerts`` -- i.e. EVADED -- no matter what Snort actually
alerted on.

That is a silent false negative, and it is not theoretical: any caller whose ids
reach past the /24 wrap (e.g. 10_000_000) gets every flow reported as evaded.
Ids are a dictionary key chosen by the caller and must never change a verdict.
"""
import sys
import numpy as np

sys.path.insert(0, "ai_agent")
sys.path.insert(0, "snort_validation")

from snort_resident_service import (
    UID_PER_NET, _uid_to_addr_port, _uid_from_alert, ResidentSnortService)


def test_uid_address_roundtrip_holds_inside_the_24():
    for uid in [0, 1, 5, 100, 249, 250, 1000]:
        ip, _port = _uid_to_addr_port(uid)
        assert _uid_from_alert(f"src {ip} ") == uid, f"roundtrip broke at uid={uid}"


def test_uid_address_roundtrip_fails_past_the_wrap():
    """Documents WHY caller ids must not reach the wire: the wrap is real."""
    far = 250 * UID_PER_NET + 3
    ip, _port = _uid_to_addr_port(far)
    assert _uid_from_alert(f"src {ip} ") != far, \
        "expected the address encoding to wrap; if this now passes, the " \
        "wrap bound moved and the guard in alert_counts_chunked needs updating"


def test_max_safe_uid_is_bounded():
    """The service must refuse to encode ids past the wrap, not mis-report them."""
    svc = ResidentSnortService()
    # _uid_base is the only thing that grows across batches.
    svc._uid_base = 10_000_000
    limit = svc._max_safe_uid()
    assert limit < 10_000_000, "limit must be below the wrapped region"
    assert svc._max_safe_uid() == limit, "limit must be a stable function of UID_PER_NET"


def test_frames_use_position_not_caller_id():
    """Two callers with different ids for the same flow must build identical bytes."""
    from scapy.all import Ether, IP, UDP

    def mk():
        p = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1234, dport=53) / b"x"
        return [p]

    svc = ResidentSnortService()
    a = svc._build_frames([(mk(), 0)], uid_base=1000)
    b = svc._build_frames([(mk(), 987654321)], uid_base=1000)
    assert a == b, "frame bytes depend on the caller's qid -- verdict can be misattributed"
    # scapy writes the address as 4 raw bytes, not ASCII.
    ip, _port = _uid_to_addr_port(1000)          # uid_base 1000 + position 0
    assert bytes(int(x) for x in ip.split(".")) in a[0]
