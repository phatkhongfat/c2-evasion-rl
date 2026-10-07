"""P0 wire-deliverability bar (plan 2026-10-07_164401-corrected-evasion-pipeline).

RED trước: các test này FAIL với fragment_ops/c2_semantics hiện tại và chỉ
xanh sau khi (a) fragment_plan_to_packets sinh fragment có Ether + TCP/UDP
header + offset 8-byte-aligned, và (b) bytes_equal_semantics gate qua
wire_deliverable().

Lưu ý signature: apply_mech(pkts, mech, client_ip=None, ownership="client").
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from scapy.all import Ether, IP, Raw, TCP, UDP  # noqa: E402

from c2_semantics import bytes_equal_semantics, wire_deliverable  # noqa: E402
from eval_pipeline import client_ip_of  # noqa: E402
from fragment_ops import split_fragments  # noqa: E402
from hidden_defender_env import HiddenDefenderEnv, apply_mech  # noqa: E402


def _pick_flows():
    """(tcp_flow, cip) với udp_flow, cip — chọn robust, không hardcode IP."""
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    tcp = udp = None
    for f in env._flows:
        cip = client_ip_of(f["flow_id"])
        for p in f["packets"]:
            if IP in p and p[IP].src == cip and Raw in p:
                ln = len(bytes(p[Raw].load))
                if TCP in p and tcp is None and ln > 24:
                    tcp = (f, cip)
                elif UDP in p and udp is None and ln > 8:
                    udp = (f, cip)
        if tcp and udp:
            break
    assert tcp and udp, "corpus test split must contain both TCP and UDP client payload flows"
    return tcp, udp


def _frags(packets):
    return [p for p in packets if IP in p
            and (int(p[IP].frag) != 0 or int(p[IP].flags) & 1)]


def test_tcp_split8_output_is_wire_deliverable():
    (f, cip), _ = _pick_flows()
    mut = apply_mech(list(f["packets"]), "split8", cip, "both")
    frags = _frags(mut)
    assert frags, "split8 must produce fragments"
    # linktype đồng nhất = linktype của capture gốc
    for p in mut:
        assert type(p) is Ether
    # offset-0 mang TCP header; continuation GIỮ proto, KHÔNG có TCP header
    for p in frags:
        if int(p[IP].frag) == 0:
            assert TCP in p
            assert int(p[IP].dataofs) * 4 == len(bytes(p[TCP])) - len(bytes(p[TCP].payload))
        else:
            assert TCP not in p
        assert int(p[IP].proto) == 6
    assert wire_deliverable(f["packets"], mut)


def test_tcp_split_cut_realigned_to_ip_boundary():
    (f, cip), _ = _pick_flows()
    mut = apply_mech(list(f["packets"]), "split8", cip, "both")
    f0 = next(p for p in mut if IP in p and p[IP].src == cip
              and int(p[IP].frag) == 0 and int(p[IP].flags) & 1
              and TCP in p and Raw in p)
    cont = [p for p in mut if IP in p and p[IP].src == cip
            and int(p[IP].frag) != 0]
    assert cont, "split8 must produce a continuation fragment"
    th = int(f0[TCP].dataofs) * 4                 # corpus: 20
    cut = len(f0[Raw].load)
    # TH + chunk0 phải kết thúc đúng ranh giới 8-byte và bằng offset của frag kế
    assert (th + cut) % 8 == 0, f"IP boundary {th + cut} not 8-aligned"
    assert int(cont[0][IP].frag) * 8 == th + cut
    # requested split8 (20+8=28 không aligned) -> cut phải bị re-align xuống 4
    assert cut < 8
    # union byte không đổi: stream bar vẫn phải qua
    assert bytes_equal_semantics(f["packets"], mut, cip)


def test_udp_split8_keeps_udp_header_only_in_first_fragment():
    _, (f, cip) = _pick_flows()
    mut = apply_mech(list(f["packets"]), "split8", cip, "both")
    frags = [p for p in _frags(mut) if p[IP].src == cip]
    assert frags, "split8 must produce fragments"
    for p in mut:
        assert type(p) is Ether
    # UDP header CHỈ trên offset-0; flow này có 6 packet client payload ->
    # mỗi packet góp đúng 1 frag mang UDP (đếm theo nhóm, không hardcode 1).
    udp_frags = [p for p in frags if UDP in p]
    assert udp_frags, "offset-0 fragments must carry the UDP header"
    assert all(int(p[IP].frag) == 0 for p in udp_frags)
    cont = [p for p in frags if int(p[IP].frag) != 0]
    assert cont, "split8 must produce a continuation fragment"
    for p in cont:
        assert UDP not in p
        assert int(p[IP].proto) == 17
    # UDP TH=8: requested cut 8 -> IP boundary 16 -> field 2 (offset tính cả TH)
    assert all(int(p[IP].frag) == 2 for p in cont)
    assert bytes_equal_semantics(f["packets"], mut, cip)


def test_wire_deliverable_rejects_legacy_style_fragments():
    """Fragment kiểu CŨ (bare IP/Raw, không Ether, không L4) — shape mà
    fragment_plan_to_packets từng sinh ra — phải bị bar từ chối."""
    (f, cip), _ = _pick_flows()
    legacy = []
    done = False
    for p in f["packets"]:
        if (not done and TCP in p and Raw in p and IP in p
                and int(p[IP].frag) == 0 and not (int(p[IP].flags) & 1)
                and p[IP].src == cip):
            data = bytes(p[Raw].load)
            if len(data) > 8:
                for fr in split_fragments(data, 8):
                    fip = IP(src=p[IP].src, dst=p[IP].dst, id=p[IP].id,
                             ttl=p[IP].ttl, frag=fr.offset // 8, flags="MF")
                    legacy.append(fip / Raw(load=fr.data))   # đúng shape cũ
                done = True
                continue
        legacy.append(p)
    assert done, "need at least one client TCP payload packet"
    assert wire_deliverable(f["packets"], legacy) is False
    assert bytes_equal_semantics(f["packets"], legacy, cip) is False


def test_bar_accepts_proper_split8():
    (f, cip), _ = _pick_flows()
    mut = apply_mech(list(f["packets"]), "split8", cip, "both")
    assert wire_deliverable(f["packets"], mut)
    assert bytes_equal_semantics(f["packets"], mut, cip)


def test_overlap8_on_tcp_keeps_original_packet():
    """TCP TH=20 không 8-aligned -> không tồn tại geometry overlap hợp lệ
    -> cơ chế không áp dụng, capture giữ nguyên (không sinh fragment rác)."""
    (f, cip), _ = _pick_flows()
    mut = apply_mech(list(f["packets"]), "overlap8", cip, "both")
    assert [bytes(p) for p in mut] == [bytes(p) for p in f["packets"]]


def test_udp_overlap8_builds_but_stays_bar_blocked():
    """UDP overlap build được (TH=8 aligned) nhưng stream bar phải CHẶN nó:
    join theo offset không policy-aware -> byte decoy lọt vào stream phục hồi.
    Đây là hành vi đã đo được hôm nay (overlap8 = 0 valid) — giữ nguyên."""
    _, (f, cip) = _pick_flows()
    mut = apply_mech(list(f["packets"]), "overlap8", cip, "both")
    frags = _frags(mut)
    assert frags, "UDP overlap8 should build fragments"
    assert bytes_equal_semantics(f["packets"], mut, cip) is False
