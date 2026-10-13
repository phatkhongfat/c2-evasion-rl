# Pipeline trung thực P0→P4: fragment đúng chuẩn + wire-deliverability + số đo lại

## 1. Goal

Chỉ số evasion rate phải phản ánh một thực tế duy nhất: gói tin đã mutate **có
thực sự deliverable được trên wire không**. Sửa `fragment_plan_to_packets` (thiếu
Ether/TCP header, offset sai chuẩn), thêm bar `wire_deliverable` vào
`bytes_equal_semantics`, đo lại toàn bộ (sweep 560 ô + 3 seed), rồi dựng thêm 4
lớp đúng thứ tự ưu tiên đã chốt: phân tầng severity (P2), ruleset tier
naive/expert (P1), learning curves (P3), cross-engine Suricata (P4).

## 2. Current context / assumptions

- Repo `/root/.hermes/c2-evasion-rl`, nhánh `packet-level-rl`, HEAD `1c6d33b`,
  test hiện tại **109 passed** (~310s). Mọi lệnh chạy với cwd này; python =
  `.venv/bin/python`.
- Con số đã commit: `ownership=both` trần **40/40 (100%)**, PPO 3 seed (7/1337/42)
  đều 40/40 — nhưng **fragment sai chuẩn** nên bar trong bộ nhớ
  (`reassembled_client_bytes`) reassemble theo offset L7 bỏ qua gap, không kiểm
  Ether/TCP header → 100% hiện tại là **giới trên cần đo lại**, không phải kết
  quả trung thực.
- Bằng chứng đã có (probe cũ, `/tmp/`): `split8.pcap` có packet fragment chỉ chứa
  Raw (linktype Ethernet nhưng record bắt đầu `0x45`, proto=0); baseline 1 flow =
  1 alert (sid 2012627). Probe "đúng chuẩn" cũ **không dùng được làm bằng chứng**
  vì nó gắn padding zero vào IP payload (corrupt bytes). Chưa ai đo split
  **cùng bytes** dưới Snort có frag3.
- Conf `snort_validation/et_open_c2/snort_et_c2.conf`: dòng 19
  `var ET_C2_RULES .../et_open_c2.rules`; dòng 64-65
  `preprocessor frag3_global` + `frag3_engine: policy first detect_anomalis` →
  tạo tier naive = copy conf, đổi biến `ET_C2_RULES`.
- Corpus đã đo: toàn bộ packet top-level **Ether**; TCP `dataofs=5` (TH=20B, không
  option); min payload client: TCP 254B, UDP 47B → luôn tồn tại cut
  8-byte-aligned. Với TH=20: `split8→4`, `split16→12`, `split24→20`; UDP TH=8:
  cut giữ nguyên.
- 14 action: `prepend4/8/12, pad16, reorder, ttl, noop, split8/16/24, overlap8,
  corrupt8, http_header_pad, length_wrapper`. Sweep
  `controls/ownership_ceiling_sweep.py`: hardcode `ownership="both"`, args
  `--split/--out/--n-flows`, load flow qua `env._flows` + `f["flow_id"]` +
  `client_ip_of`, trả row dict (có `evaded`, `semantics_ok`, `baseline_alert`).
- `eval_pipeline.py`: `run_snort_single(pcap, conf=None, logdir=None, timeout=600)
  -> int` (đếm dòng `_ALERT_LINE`, **chưa lấy sid**); `score_flow_real(pkts,
  client_ip, attempt_id, mech, *, ownership=..., conf=SNORT_CONF)` — conf đã
  parameterized sẵn; helper `mutate_client_only` (dòng 109) + `translate_source`
  (dòng 366) đều import được.
- `c2_semantics.py` import sẵn `from scapy.all import IP, TCP, UDP` — chỉ cần
  thêm `from collections import Counter`.
- Bar dùng chung MỘT hàm: env `semantics_intact` → `bytes_equal_semantics`; eval
  `score_flow_real` → cùng hàm (`tests/test_semantics_bar_agreement.py` bắt buộc
  đồng nhất) → **sửa một hàm = cả hai nơi được gating**.
- 2 caller build fragment: `ai_agent/hidden_defender_env.py::apply_mech` (nhánh
  `split` ~dòng 209-221, nhánh `overlap8` ~dòng 222-232) và
  `snort_validation/eval_pipeline.py::mutate_client_only` (split 124-143,
  overlap8 144-160). Hàm gốc: `snort_validation/fragment_ops.py`
  `fragment_plan_to_packets` dòng 79-111.
- Test sẽ động tới: `tests/test_fragment_ops.py::test_fragment_plan_to_packets_preserves_all_bytes`
  (assert offsets `[0,1,0]` → sẽ thành `[0,2,1]`), `tests/test_evaluation_fixes.py`
  (dòng 91-113: split8/payloads/`bytes_equal_semantics` True),
  `tests/test_ownership_model.py::test_bar_accepts_fragmentation_of_server_stream`
  (hand-build fragment bare IP/TCP — vẫn True sau fix nhờ re-cut).
- Log train cũ `/tmp/trainb_s{7,1337,42}.log` có dòng
  `  [*] epoch  0: 64 queries, 0/64 flows valid this epoch (0.0%)` → làm fixture
  dev cho P3.
- Đo dài: sweep ~6400s/lần, train ~vài giờ/seed → gộp vào 1 script nền
  tuần tự, báo notify khi xong.
- Quy ước TDD: mỗi task = test đỏ → implement tối thiểu → xanh → commit. Không
  bao giờ nới lỏng bar để làm test xanh.

## 3. Architecture / định hướng

Sửa **một hàm sinh fragment** (`fragment_plan_to_packets`) để mọi packet đi qua
Ether-wrapped, transport-header chỉ nằm ở fragment offset-0, offset tính theo
IP-payload space và luôn chia hết 8 (re-cut cắt nếu cần, chỉ **di chuyển** byte,
không phát minh). Bar thêm **một cổng mới** (`wire_deliverable`) ngay đầu
`bytes_equal_semantics` — đúng một điểm gating cho cả env lẫn eval. Số đo lại
được sinh ra từ cùng pipeline đó, rồi các phase P2→P4 chỉ **đọc thêm metadata
(sid/classtype), đổi conf, parse log, đối chiếu engine** — không sửa metric.

## 4. Phase 1 (P0) — Fragment đúng chuẩn + bar `wire_deliverable` + probe cổng D1

### Task 1.1 — Stub `wire_deliverable` (để test RED đúng kiểu, không ImportError)

`snort_validation/c2_semantics.py`, đặt **ngay trước** `bytes_equal_semantics`:

```python
def wire_deliverable(original_packets, mutated_packets) -> bool:
    """PLACEHOLDER — replaced in Task 1.6. Stub keeps imports valid while the
    failing tests (tests/test_wire_deliverability.py) are written first."""
    return True
```

### Task 1.2 — Viết test RED: `tests/test_wire_deliverability.py` (file mới)

```python
"""P0 wire-deliverability bar (plan 2026-10-07_164401-corrected-evasion-pipeline).

RED trước: các test này FAIL với fragment_ops/c2_semantics hiện tại và chỉ
xanh sau khi (a) fragment_plan_to_packets sinh fragment có Ether + TCP/UDP
header + offset 8-byte-aligned, và (b) bytes_equal_semantics gate qua
wire_deliverable().
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
                if TCP in p and tcp is None:
                    tcp = (f, cip)
                elif UDP in p and udp is None:
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
    mut = apply_mech(list(f["packets"]), "split8", "both")
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
    mut = apply_mech(list(f["packets"]), "split8", "both")
    f0 = next(p for p in mut if IP in p and int(p[IP].frag) == 0
              and int(p[IP].flags) & 1 and TCP in p and Raw in p)
    cont = [p for p in mut if IP in p and int(p[IP].frag) != 0]
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
    mut = apply_mech(list(f["packets"]), "split8", "both")
    frags = _frags(mut)
    assert frags, "split8 must produce fragments"
    for p in mut:
        assert type(p) is Ether
    udp_frags = [p for p in frags if UDP in p]
    assert len(udp_frags) == 1 and int(udp_frags[0][IP].frag) == 0
    cont = [p for p in frags if int(p[IP].frag) != 0]
    assert cont
    for p in cont:
        assert UDP not in p
        assert int(p[IP].proto) == 17
    # UDP TH=8: requested cut 8 -> IP boundary 16 -> field 2 (offset tính cả TH)
    assert int(cont[0][IP].frag) == 2
    assert bytes_equal_semantics(f["packets"], mut, cip)


def test_wire_deliverable_rejects_legacy_style_fragments():
    """Fragment kiểu CŨ (bare IP/Raw, không Ether, không L4) — Shape mà
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
    mut = apply_mech(list(f["packets"]), "split8", "both")
    assert wire_deliverable(f["packets"], mut)
    assert bytes_equal_semantics(f["packets"], mut, cip)


def test_overlap8_on_tcp_keeps_original_packet():
    """TCP TH=20 không 8-aligned -> không tồn tại geometry overlap hợp lệ
    -> cơ chế không áp dụng, capture giữ nguyên (không sinh fragment rác)."""
    (f, cip), _ = _pick_flows()
    mut = apply_mech(list(f["packets"]), "overlap8", "both")
    assert [bytes(p) for p in mut] == [bytes(p) for p in f["packets"]]


def test_udp_overlap8_builds_but_stays_bar_blocked():
    """UDP overlap build được (TH=8 aligned) nhưng stream bar phải CHẶN nó:
    join theo offset không policy-aware -> byte decoy lọt vào stream phục hồi.
    Đây là hành vi đã đo được hôm nay (overlap8 = 0 valid) — giữ nguyên."""
    _, (f, cip) = _pick_flows()
    mut = apply_mech(list(f["packets"]), "overlap8", "both")
    frags = _frags(mut)
    assert frags, "UDP overlap8 should build fragments"
    assert bytes_equal_semantics(f["packets"], mut, cip) is False
```

Chạy để xác nhận RED (kỳ vọng):

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest \
  tests/test_wire_deliverability.py -q 2>&1 | tail -20
```

Kỳ vọng: **FAILED ≥ 5** — `test_tcp_split8_output_is_wire_deliverable`
(type không phải Ether), `test_tcp_split_cut_realigned_to_ip_boundary`
(TCP không nằm ở frag0 / StopIteration), `test_udp_split8_keeps_udp_header_only_in_first_fragment`
(UDP ở mọi fragment, field ≠ 2), `test_wire_deliverable_rejects_legacy_style_fragments`
(stub trả `True`), `test_overlap8_on_tcp_keeps_original_packet`
(capture có fragment rác). Ghi lại đúng số failed vào biên bản.

### Task 1.3 — Thay `fragment_plan_to_packets` trong `snort_validation/fragment_ops.py`

Thay **toàn bộ hàm** (dòng ~79-111, giữ nguyên `Fragment`, `split_fragments`,
`overlap_fragments`, `reorder_fragments` bên trên). Mã đầy đủ, copy-paste được:

```python
def fragment_plan_to_packets(packets, frags, target_idx):
    """Turn a Fragment plan into REAL, wire-deliverable IP fragments.

    Hai tính chất mà bản cũ vi phạm (bắt bởi tests/test_wire_deliverability.py):

    1. Link layer: mỗi fragment được bọc lại bằng CHÍNH link header của packet
       mục tiêu (Ether trên corpus) -> pcap giữ một linktype đồng nhất, NIC
       endpoint nhận được frame (bản cũ emit record trần IP trên linktype
       Ethernet -> libpcap/Snort báo "Inconsistent linktypes").
    2. Địa chỉ: offset tính trong không gian IP payload -- transport header
       CHỈ nằm trên fragment offset-0, `proto` được giữ trên MỌI fragment
       (bản cũ để proto=0 cho TCP), và mỗi điểm cắt rơi đúng ranh giới
       8-byte. Khi TH làm điểm cắt yêu cầu không aligned (TCP TH=20:
       split8 -> 28 không chia hết 8) thì cắt được re-align XUỐNG ranh giới
       hợp lệ gần nhất (split8 -> 4, split16 -> 12, split24 -> 20); byte được
       DI CHUYỂN giữa các chunk, không bao giờ bịa ra byte mới.

    Raises ValueError khi không tồn tại hình học hợp lệ (mã overlap cần TH
    8-aligned: UDP được, TCP 20-byte không được). Caller bắt lỗi và giữ nguyên
    packet gốc -> cơ chế "không áp dụng" thay vì sinh packet rác.
    """
    from scapy.all import IP, Raw, TCP, UDP

    if target_idx < 0 or target_idx >= len(packets):
        raise IndexError(f"target_idx {target_idx} out of range (n={len(packets)})")
    pkt = packets[target_idx]
    if IP not in pkt:
        raise ValueError("target packet has no IP layer to fragment")
    if Raw not in pkt:
        raise ValueError("target packet has no payload to fragment")
    ip = pkt[IP]

    # transport header: chỉ nằm trên fragment offset-0
    th_layer, th_len = None, 0
    if TCP in pkt:
        th_layer = pkt[TCP].copy()
        del th_layer.payload
        th_len = len(bytes(th_layer))          # == dataofs*4 khi parse từ pcap
    elif UDP in pkt:
        th_layer = pkt[UDP].copy()
        del th_layer.payload
        th_len = len(th_layer)                 # == 8
    proto = int(ip.proto) if ip.proto is not None else (
        6 if TCP in pkt else 17 if UDP in pkt else 0)

    # link header: giữ ĐÚNG class của packet mục tiêu (Ether trên corpus)
    outer = None
    if not isinstance(pkt, IP):
        outer = pkt.copy()
        del outer.payload

    n = len(frags)
    idx_sorted = sorted(range(n), key=lambda i: frags[i].offset)
    data = [bytes(frags[i].data) for i in idx_sorted]
    if any(not d for d in data):
        raise ValueError("fragment plan contains an empty chunk")

    dup = len({frags[i].offset for i in idx_sorted}) != n
    ip_off_sorted = []
    if dup:
        # overlap: chunk đến TRƯỚC có offset L7=0 mang TH (IP offset 0); mọi
        # chunk khác bắt đầu tại th_len + offset L7 của nó. RFC 791 buộc các
        # offset đó chia hết 8 -> th_len phải 8-aligned (UDP: 8 ok; TCP
        # 20-byte: không -> caller giữ nguyên packet).
        if th_len % 8:
            raise ValueError(
                f"overlap needs an 8-byte-aligned transport header (th_len={th_len})")
        for j, i in enumerate(idx_sorted):
            off = 0 if j == 0 else th_len + frags[i].offset
            if off % 8:
                raise ValueError(f"overlap cut at IP offset {off} is not 8-aligned")
            ip_off_sorted.append(off)
    else:
        # split liên tục: re-align từng điểm cắt XUỐNG bội 8 gần nhất bằng
        # cách DI CHUYỂN byte giữa 2 chunk kề (thứ tự + tổng byte giữ nguyên).
        cum = 0
        for j in range(n - 1):
            cum += len(data[j])
            delta = (th_len + cum) % 8
            if delta:
                if cum - delta <= 0:
                    raise ValueError(
                        f"no 8-byte-aligned cut near {cum} (th_len={th_len})")
                move = cum - delta
                data[j], data[j + 1] = data[j][:-move], data[j][-move:] + data[j + 1]
                cum -= move
        acc = 0
        for j, d in enumerate(data):
            ip_off_sorted.append(acc)
            acc += (th_len + len(d)) if j == 0 else len(d)

    # ánh xạ về thứ tự ĐẾN (arrival order) — pcap phải giữ đúng thứ tự gói
    ip_off = [0] * n
    data_orig = [None] * n
    for pos, orig_i in enumerate(idx_sorted):
        ip_off[orig_i] = ip_off_sorted[pos]
        data_orig[orig_i] = data[pos]
    if any(o % 8 for o in ip_off):
        raise ValueError(f"unaligned fragment offsets {ip_off}")

    # fragment cuối tại offset lớn nhất (đến sau cùng) bỏ cờ MF = hết datagram
    max_off = max(ip_off)
    terminator = max(i for i in range(n) if ip_off[i] == max_off)

    out = []
    for i in range(n):
        fip = IP(src=ip.src, dst=ip.dst, id=ip.id, ttl=ip.ttl, proto=proto,
                 frag=ip_off[i] // 8,
                 flags="MF" if i != terminator else 0)
        seg = outer.copy() / fip if outer is not None else fip
        if ip_off[i] == 0 and th_layer is not None:
            seg = seg / th_layer.copy()
        seg = seg / Raw(load=data_orig[i])
        out.append(seg)
    return out
```

Lưu ý scapy: `outer / fip` không mutate `outer` nhưng `outer.copy()` mỗi vòng
là bắt buộc vì ta `del payload` một lần trên bản gốc. Checksum: fragment dựng
mới (`chksum=None`) -> scapy tính lại khi `wrpcap`/`bytes()`; header TCP/UDP
copy từ packet gốc giữ nguyên giá trị checksum đã parse.

### Task 1.4 — Guard `ValueError` ở cả 2 caller

**File A — `ai_agent/hidden_defender_env.py`, trong `apply_mech`**
(tìm anchor `if mech.startswith("split"):`, nhánh chạy ~dòng 206-232; GIỮ
nguyên dòng import `fragment_plan_to_packets, split_fragments` /
`fragment_plan_to_packets, overlap_fragments` đang có trong từng nhánh).
Thay **phần thân** từ `off = int(mech[5:])` (nhánh split) và từ
`payload = bytes(out[tgt[0]][Raw].load)` (nhánh overlap) thành:

```python
        if mech.startswith("split"):
            # (giữ nguyên dòng import fragment_ops đang có trong nhánh này)
            off = int(mech[5:])
            rebuilt = []
            for i, p in enumerate(out):
                out_frags = None
                if i in tgt_idx:
                    payload = bytes(p[Raw].load)
                    if 0 < off < len(payload):
                        try:
                            out_frags = fragment_plan_to_packets(
                                out, split_fragments(payload, off), i)
                        except ValueError:
                            out_frags = None   # không có hình học hợp lệ: giữ packet
                if out_frags is not None:
                    rebuilt.extend(out_frags)
                else:
                    rebuilt.append(p)
            return rebuilt
        if mech == "overlap8":
            # (giữ nguyên dòng import fragment_ops đang có trong nhánh này)
            rebuilt = []
            for i, p in enumerate(out):
                out_frags = None
                if i == tgt[0]:
                    payload = bytes(p[Raw].load)
                    try:
                        out_frags = fragment_plan_to_packets(
                            out, overlap_fragments(payload, 8), i)
                    except ValueError:
                        out_frags = None
                if out_frags is not None:
                    rebuilt.extend(out_frags)
                else:
                    rebuilt.append(p)
            return rebuilt
```

**File B — `snort_validation/eval_pipeline.py`, trong `mutate_client_only`**
(dòng 124-160; anchor `for split in ("split8", "split16", "split24"): ...`
và `if mech == "overlap8":`). Thay thân 2 nhánh theo đúng mẫu trên (cùng
pattern try/except ValueError -> giữ packet gốc). Lưu ý: hàm này build
`rebuilt`/`rebuilt` list riêng, ánh xạ `target_idx` là chỉ số packet trong
danh sách truyền vào — giữ nguyên cách đếm chỉ số hiện tại của nó.

Kiểm tra nhanh cả 2 file compile + RED chưa đổi:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -c "
import sys; sys.path[:0]=['ai_agent','snort_validation']
from hidden_defender_env import apply_mech
from eval_pipeline import mutate_client_only
print('imports OK')" && .venv/bin/python -m pytest \
  tests/test_wire_deliverability.py -q 2>&1 | tail -5
```

Kỳ vọng: `imports OK`; pytest vẫn RED (các test cấu trúc chưa xanh vì
`wire_deliverable` vẫn là stub + test legacy chưa bị từ chối) — chạy lại ở
Task 1.6.

### Task 1.5 — Cập nhật test cũ đang encode hình học fragment CŨ

1. `tests/test_fragment_ops.py::test_fragment_plan_to_packets_preserves_all_bytes`
   (dòng ~49): assert `p[IP].frag == [0, 1, 0]` (offset L7/8) -> **`[0, 2, 1]`**
   (offset IP-space gồm UDP TH=8: decoy→IP 0, tail→IP 16→field 2, real→IP 8→field 1).
   Assert `flags == [1, 0, 1]` **giữ nguyên** (terminator vẫn là tail).
   Sửa kèm comment:
   `# IP-space offsets: UDP TH=8 counted -> decoy=0, tail=16/8=2, real=8/8=1`
2. Chạy toàn bộ suite hiện có, chỉ sửa những assert encode rõ geometry cũ
   (bare-IP / offset L7 / fragment không có L4), mỗi lần sửa ghi lý do vào
   commit message. **Tuyệt đối không** nới lỏng bar (`bytes_equal_semantics`,
   `semantics_intact`, `valid_evasion`) hay đổi expected về hướng "cho qua".
3. Hai test dùng replica (`real_snort=False`) có thể đổi hành vi nếu replica
   nhìn cấu trúc packet: `tests/test_mechanisms_ab.py:143`
   (`best["mech"] == "split8"`) và `tests/test_policy_diversity.py:84`
   (reward `split8`). Nếu 2 test này đỏ: **điều tra** replica xem nó thấy gì
   trên fragment mới (in/log từng packet), báo cáo vào commit — không được
   sửa assertion cho xanh mà không hiểu nguyên nhân (xem R7).

### Task 1.6 — Thay stub `wire_deliverable` bằng bản thật + gate bar

**6a.** `snort_validation/c2_semantics.py` — thêm import (nếu chưa có):
`from collections import Counter` (file đã import `IP, TCP, UDP` từ scapy).

**6b.** Thay hàm stub bằng bản đầy đủ (đặt ngay trước `bytes_equal_semantics`):

```python
def wire_deliverable(original_packets, mutated_packets) -> bool:
    """True iff `mutated_packets` có thể thực sự đi lên wire và đến endpoint
    với CÙNG bytes:

    * một link type đồng nhất, khớp capture gốc (pcap trộn record Ether với
      record IP trần bị libpcap/Snort từ chối: "Inconsistent linktypes");
    * cấu trúc fragment hợp lệ: offset-0 mang transport header, continuation
      GIỮ nguyên `proto` và không mang transport header;
    * theo từng source IP, multiset IP datagram sau reassembly (offset 8-byte,
      byte đến SAU thắng khi trùng offset — chính sách endpoint phổ biến)
    bằng multiset của bản gốc.

    Đây là gate mà pipeline từng thiếu: bar cũ phục hồi payload bytes trong
    bộ nhớ bằng offset bookkeeping bỏ qua gap, nên nó CẶT CỨU cả fragment
    hỏng mà fragment_plan_to_packets từng sinh ra (không Ether, không L4,
    proto=0) — pcap mà không endpoint nào nhận được vẫn được tính là
    semantics-preserving evasion. Xem tests/test_wire_deliverability.py.
    """
    if not original_packets or not mutated_packets:
        return False
    link = type(mutated_packets[0])
    if link is not type(original_packets[0]):
        return False
    if any(type(p) is not link for p in mutated_packets):
        return False

    def _is_frag(ip):
        return int(ip.frag) != 0 or bool(int(ip.flags) & 0x1)

    def _datagrams(packets):
        """-> {src_ip: Counter(datagram_bytes)} hoặc None nếu không phục hồi nổi."""
        acc = {}
        i, n = 0, len(packets)
        while i < n:
            p = packets[i]
            if IP not in p:
                i += 1
                continue
            ip = p[IP]
            if not _is_frag(ip):
                acc.setdefault(ip.src, Counter())[bytes(ip.payload)] += 1
                i += 1
                continue
            # một dãy fragment (cắt tại fragment offset-0 kế tiếp, cùng id/src/dst)
            gid, gsrc, gdst = int(ip.id), ip.src, ip.dst
            run = []
            while i < n and IP in packets[i]:
                q = packets[i][IP]
                if (not _is_frag(q) or int(q.id) != gid
                        or q.src != gsrc or q.dst != gdst):
                    break
                if int(q.frag) == 0 and run:
                    break
                run.append(packets[i])
                i += 1
            buf, cleared_end = bytearray(), -1
            for r in run:
                rip = r[IP]
                off = int(rip.frag) * 8
                chunk = bytes(rip.payload)     # IP payload = TH + data
                if not chunk:
                    return None                # fragment rỗng: không hợp lệ
                if off > len(buf):
                    return None                # có gap: không phục hồi nổi
                end = off + len(chunk)
                if end > len(buf):
                    buf.extend(chunk[len(buf) - off:])
                else:
                    buf[off:end] = chunk       # trùng offset: byte sau thắng
                if not (int(rip.flags) & 0x1):
                    cleared_end = max(cleared_end, end)
            if cleared_end != len(buf):
                return None                    # dãy fragment không kết thúc trọn vẹn
            acc.setdefault(gsrc, Counter())[bytes(buf)] += 1
        return acc

    a = _datagrams(original_packets)
    b = _datagrams(mutated_packets)
    if a is None or b is None:
        return False
    if a.keys() != b.keys():
        return False
    return all(a[k] == b[k] for k in a)
```

**6c.** `bytes_equal_semantics` — thêm gate dòng đầu + cập nhật docstring:

```python
def bytes_equal_semantics(orig_packets, mut_packets, client_ip) -> bool:
    """True iff the client→server payload streams are byte-for-byte identical
    in BOTH directions **and** the mutated capture is wire-deliverable
    (wire_deliverable). Checked BEFORE assembly so a capture no endpoint
    could ever reassemble can never pass the bar.
    """
    if not wire_deliverable(orig_packets, mut_packets):
        return False
    ... (phần thân hiện có giữ nguyên) ...
```

Không sửa bất kỳ call site nào: env (`semantics_intact` → reward) và eval
(`score_flow_real` → `semantics_ok`/`valid_evasion`) đều đi qua đúng hàm này,
nên `test_semantics_bar_agreement` giữ nguyên tính đồng nhất.

Kiểm tra GREEN (kỳ vọng):

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest \
  tests/test_wire_deliverability.py tests/test_fragment_ops.py \
  tests/test_ownership_model.py tests/test_evaluation_fixes.py -q 2>&1 | tail -5
```

Kỳ vọng: **passed, 0 failed** (kể cả test legacy trả `False`, test UDP
offsets `[0,2,1]`, `test_bar_accepts_fragmentation_of_server_stream` vẫn
True — fragment của nó re-cut về 4 byte nhưng union byte không đổi).

### Task 1.7 — Full suite trước khi đo

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests -q 2>&1 | tail -6
```

Kỳ vọng: **passed = 109 cũ + 8 test mới = 121** (hoặc nhiều hơn nếu
Task 1.5 thêm test cho assertion đã cập nhật), **0 failed**. Thời gian chạy
~300-360s. Nếu `test_mechanisms_ab` / `test_policy_diversity` đỏ → xử lý
theo Task 1.5 bước 3 (điều tra replica, không sửablind).

### Task 1.8 — Probe quyết định D1: split CÙNG BYTES có evaded Snort thật không?

Đây là số phận của toàn bộ kết quả. Viết `/tmp/probe_recut.py` — chạy pipeline
THẬT (`score_flow_real`, gồm translate + wrpcap + Snort conf frag3
`policy first`) trên 2 flow đại diện:

```python
#!/usr/bin/env python3
"""D1 gate: đo split CÙNG BYTES (fragment đúng chuẩn) trên Snort thật."""
import sys
sys.path[:0] = ["/root/.hermes/c2-evasion-rl/ai_agent",
                "/root/.hermes/c2-evasion-rl/snort_validation"]
from hidden_defender_env import HiddenDefenderEnv
from eval_pipeline import client_ip_of, score_flow_real

env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
from scapy.all import IP, Raw, TCP, UDP
picked = {}
for f in env._flows:
    cip = client_ip_of(f["flow_id"])
    for p in f["packets"]:
        if IP in p and p[IP].src == cip and Raw in p:
            key = "tcp" if TCP in p else ("udp" if UDP in p else None)
            if key and key not in picked:
                picked[key] = (f, cip)
    if len(picked) == 2:
        break

aid = 0
for key in sorted(picked):
    f, cip = picked[key]
    base = score_flow_real(f["packets"], cip, aid, None); aid += 1
    print(f"{key} {f['flow_id']} baseline: alerts={base['n_alerts']} "
          f"sids={base['sids']} sem={base['semantics_ok']}")
    for mech in ("split8", "split16", "split24", "overlap8"):
        r = score_flow_real(f["packets"], cip, aid, mech, ownership="both"); aid += 1
        verdict = "EVADED" if r["evaded"] else "ALERT"
        print(f"{key} {f['flow_id']} {mech:9s}: {verdict} "
              f"alerts={r['n_alerts']} sem={r['semantics_ok']} valid={r['valid_evasion']}")
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python /tmp/probe_recut.py 2>&1 | grep -E 'baseline|split|overlap'
```

**Cổng D1 — hai nhánh, xử lý bắt buộc:**

- **Nhánh A** (split: `alerts=0 sem=True valid=True`): fragmentation CÙNG BYTES
  vẫn vượt Snort (frag3 không phục hồi đủ để content match) → tiếp tục toàn
  bộ Phase 2, 3 và chạy Stage A (sweep + retrain như kế hoạch đã chốt).
- **Nhánh B** (split: `alerts=1` → `evaded=False`, tức frag3 dựng lại được
  stream giống gốc và rule nổ lại): trần "100%" hôm nay chủ yếu đến từ packet
  HỎNG. **DỪNG, báo cáo user ngay** (reply + hỏi bằng `clarify`): tiếp tục
  sweep để đo trần thật (kỳ vọng rơi mạnh, có thể ~0 valid vì mọi cơ chế
  đổi byte đều bị bar chặn) nhưng **tạm hoãn 3 job retrain** cho tới khi user
  chọn: (i) chạy đủ sweep + train với kết quả trung thực, hay (ii) chỉ sweep +
  rồi bàn lại (overlap policy-aware bar, v.v.). Sweep full vẫn chạy được vì
  đây là số đo chính thức.

Ghi kết quả probe vào biên bản (commit message / THREAT_MODEL) — probe này
thay thế probe `/tmp/probe_proper_frag.py` cũ vốn gắn padding zero vào IP
payload (corrupt byte, không phải split trung thực).

### Task 1.9 — Commit 1 (TDD: RED→GREEN→commit)

```bash
cd /root/.hermes/c2-evasion-rl && git add snort_validation/fragment_ops.py \
  snort_validation/c2_semantics.py snort_validation/eval_pipeline.py \
  ai_agent/hidden_defender_env.py tests/test_wire_deliverability.py \
  tests/test_fragment_ops.py && git commit -m "fix(P0): wire-deliverable fragments + bar gate
- fragment_plan_to_packets: Ether wrapper, TH only on frag0, proto kept,
  cuts re-aligned to 8-byte IP boundaries (split8/16/24 -> 4/12/20 on TCP/20)
- ValueError -> callers keep original packet (overlap8-TCP = not applicable)
- bytes_equal_semantics now gates on wire_deliverable (uniform linktype +
  fragment structure + per-direction datagram reassembly == original)
- tests: 8 new (RED first), legacy offset assertion [0,1,0] -> [0,2,1]" && git log --oneline -1
```

Kỳ vọng: commit tạo, `git log --oneline -1` in đúng SHA mới trên
`packet-level-rl`.

## 5. Phase 2 (P2) — Lấy sid từng ô + stratify theo classtype (metric trung thực)

Mục tiêu: 100%/40% gộp `trojan-activity` với `policy-violation` (Informational)
là headline bị phình. Phase này cho ra bảng evasion rate **theo classtype**.

### Task 2.1 — `_run_snort` trả `(count, sids)` trong `snort_validation/eval_pipeline.py`

Hiện `run_snort_single` (dòng ~302-329) đếm dòng khớp `_ALERT_LINE` rồi trả
`int`. Refactor (giữ nguyên hành vi cũ qua wrapper):

```python
_SID_RE = re.compile(r"\[\d+:(\d+):\d+\]")   # đặt cạnh _ALERT_LINE

def _run_snort(pcap, conf=None, logdir=None, timeout=600):
    """Run Snort once; return (alert_count, fired_sids).
    Tách từ run_snort_single: count phục vụ score lịch sử, sid phục vụ
    stratify theo classtype (plan P2)."""
    ... (toàn bộ thân run_snort_single hiện có, gồm chuẩn hóa logdir, chạy
         snort, returncode, quét file .log) ...
    n_alerts = 0
    sids = set()
    for f in os.listdir(logdir):
        if f.endswith(".log"):
            with open(os.path.join(logdir, f)) as fh:
                for line in fh:
                    if _ALERT_LINE.search(line):
                        n_alerts += 1
                        sids.update(int(s) for s in _SID_RE.findall(line))
    return n_alerts, sorted(sids)


def run_snort_single(pcap, conf=None, logdir=None, timeout=600) -> int:
    """Back-compat wrapper: chỉ trả số alert như trước."""
    return _run_snort(pcap, conf=conf, logdir=logdir, timeout=timeout)[0]
```

### Task 2.2 — `score_flow_real` trả thêm `"sids"`

Trong `score_flow_real` (dòng ~349+): thay
`n_alerts = run_snort_single(pcap, ...)` thành
`n_alerts, fired_sids = _run_snort(pcap, ...)`; trong dict trả về thêm
`"sids": fired_sids`. Các trường khác giữ nguyên. Chú thích dòng:
`# fired sids -> P2 severity stratification`.

### Task 2.3 — Sweep ghi sids vào JSON

`controls/ownership_ceiling_sweep.py`: mỗi row `rows.append({...})` thêm 2
khóa: `"sids": r.get("sids", [])` và `"baseline_sids": base.get("sids", [])`
(lưu ý: `base` đã được tính ở đầu vòng — nếu biến chỉ còn bool
`base["evaded"]`, giữ lại dict `base` đầy đủ thay vì chỉ bool). Kiểm tra biến
`base` hiện tại giữ `evaded` ở đâu rồi sửa cho cả 2 chỗ đọc.

### Task 2.4 — Module `snort_validation/alert_strat.py`

```python
"""Stratify sweep results theo CLASSTYPE của rule đã nổ (plan P2).

Cùng một số "evade" nhìn khác hẳn khi tách:
  trojan-activity / exploit     = mục tiêu thật của C2 evasion
  policy-violation (DHT/P2P)    = Informational, không phải detec malware
"""
import json
import re
from collections import defaultdict
from pathlib import Path


def sid_classtypes(rules_path) -> dict:
    """{sid: classtype} đọc trực tiếp từ file .rules (ET: sid + classtype
    cùng dòng)."""
    out = {}
    for line in Path(rules_path).read_text(errors="ignore").splitlines():
        ms, mc = re.search(r"sid:(\d+);", line), re.search(r"classtype:([^;]+);", line)
        if ms and mc:
            out[int(ms.group(1))] = mc.group(1).strip()
    return out


def stratify(sweep_path, rules_path) -> dict:
    """-> {classtype: {mech: {"flows": n, "evaded": n, "valid": n}}}

    - một flow thuộc nhóm G nếu baseline_sids của nó chứa ≥1 sid map sang G
      (flow có thể thuộc nhiều nhóm; mỗi nhóm chỉ đếm 1 lần/flow)
    - "valid" = valid_evasion của ô (mech, flow) đó
    """
    data = json.loads(Path(sweep_path).read_text())
    ct = sid_classtypes(rules_path)
    rows = data["rows"]
    flows = {}
    for r in rows:
        flows.setdefault(r["flow_id"], r.get("baseline_sids", []))
    groups = defaultdict(set)
    for fid, sids in flows.items():
        for s in sids:
            groups[ct.get(s, "unknown")].add(fid)
    out = {}
    for g, fids in sorted(groups.items()):
        per = {}
        for r in rows:
            if r["flow_id"] not in fids:
                continue
            d = per.setdefault(r["mech"], {"flows": 0, "evaded": 0, "valid": 0})
            d["flows"] += 1
            d["evaded"] += bool(r["evaded"])
            d["valid"] += bool(r.get("valid_evasion"))
        out[g] = per
    return out
```

### Task 2.5 — CLI `controls/alert_stratification.py`

```python
#!/usr/bin/env python3
"""In bảng evasion rate theo classtype (plan P2)."""
import argparse, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
from alert_strat import stratify

ap = argparse.ArgumentParser()
ap.add_argument("--sweep", default=str(ROOT / "snort_validation/reports/ceiling_ownership_both_v2.json"))
ap.add_argument("--rules", default=str(ROOT / "snort_validation/et_open_c2/et_open_c2.rules"))
args = ap.parse_args()
res = stratify(args.sweep, args.rules)
for g, per in res.items():
    print(f"\n### classtype: {g}")
    print("| mech | flows | evaded | valid |")
    print("|---|---|---|---|")
    for m, d in sorted(per.items(), key=lambda kv: -kv[1]["valid"]):
        print(f"| {m} | {d['flows']} | {d['evaded']} | {d['valid']} |")
```

### Task 2.6 — Test (không cần Snort)

`tests/test_alert_stratification.py`: fixture 2 dòng rules
(`alert tcp any any -> any $HTTP_PORTS (content:"x"; sid:1001; classtype:trojan-activity;)`
và `sid:1002; classtype:policy-violation;`) + fixture JSON sweep 3 rows
(2 flow, baseline_sids [1001] và [1002], 1 ô valid=True) → assert
`sid_classtypes` map đúng 2 sid và `stratify` cho đúng dict kỳ vọng
(nhóm trojan-activity: 1 flow; policy-violation: 1 flow; ô valid nằm ở nhóm
đúng). RED → implement → GREEN.

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest \
  tests/test_alert_stratification.py -q 2>&1 | tail -3
```

Kỳ vọng sau khi xong Task 2.4-2.6: **passed**. Chạy lại 4 test đánh giá
(`test_evaluation_fixes`, `test_eval_cli`, `test_semantics_bar_agreement`,
`test_ownership_model`) để chắc chắn Task 2.1-2.2 không đổi hành vi:
`pytest tests/test_evaluation_fixes.py tests/test_eval_cli.py tests/test_semantics_bar_agreement.py -q`
→ **passed** (count trả về vẫn `int`).

### Commit 2

```bash
cd /root/.hermes/c2-evasion-rl && git add snort_validation/eval_pipeline.py \
  snort_validation/alert_strat.py controls/ownership_ceiling_sweep.py \
  controls/alert_stratification.py tests/test_alert_stratification.py && \
git commit -m "feat(P2): fired-sid collection + classtype stratification
- _run_snort returns (n_alerts, sids); run_snort_single wraps for compat
- score_flow_real + sweep rows carry sids/baseline_sids
- alert_strat.stratify: evasion rates grouped by rule classtype" && \
git log --oneline -1
```

## 6. Phase 3 (P1) — Trục ruleset: naive vs expert (thiết kế LCN25) + bắn Stage A

### Task 3.1 — `controls/make_naive_ruleset.py`

Tier naive = **đúng tập rule nổ trên baseline corpus** (đo được, không
hand-pick — lặp lại thiết kế naive-vs-expert của LCN25 nhưng số liệu):

```python
#!/usr/bin/env python3
"""Build the NAIVE ruleset tier: exactly the ET-Open rules that fire on this
corpus's baseline flows (measured, not hand-picked — the LCN25
MovingTargetOffense naive-vs-expert axis)."""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=str(ROOT / "snort_validation/et_open_c2/et_open_c2.rules"))
    ap.add_argument("--out", default=str(ROOT / "snort_validation/et_open_c2/naive.rules"))
    ap.add_argument("--report", default=str(ROOT / "snort_validation/reports/baseline_sids_test.json"))
    args = ap.parse_args()

    from eval_pipeline import client_ip_of, score_flow_real
    from hidden_defender_env import HiddenDefenderEnv

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    per_flow = {}
    for fi, f in enumerate(env._flows):
        cip = client_ip_of(f["flow_id"])
        r = score_flow_real(f["packets"], cip, fi % 250, None)   # mech=None: baseline
        per_flow[f["flow_id"]] = r["sids"]
    sids = sorted({s for v in per_flow.values() for s in v})
    want = set(sids)

    keep, total = [], 0
    for line in Path(args.rules).read_text(errors="ignore").splitlines(keepends=True):
        total += 1
        m = re.search(r"sid:(\d+);", line)
        if m and int(m.group(1)) in want:
            keep.append(line)
    if not keep:
        sys.exit("ERROR: naive tier would be empty — check _SID_RE / rules format")
    Path(args.out).write_text("".join(keep))
    Path(args.report).write_text(json.dumps(
        {"sids": sids, "per_flow": per_flow}, indent=1))
    print(f"fired sids={sids}; kept {len(keep)}/{total} rule lines -> {args.out}")

if __name__ == "__main__":
    main()
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/make_naive_ruleset.py
```

Kỳ vọng: in `fired sids=[2008581, 2008583, 2008585, 2012627, ...]` và
`kept ≥ 4/21374 rule lines`; file `naive.rules` + `reports/baseline_sids_test.json` tồn tại.
Nếu `kept=0` → định dạng sid không như dự kiến, sửa regex rồi chạy lại (không commit khi 0).

### Task 3.2 — Conf tier naive

```bash
cd /root/.hermes/c2-evasion-rl && cp snort_validation/et_open_c2/snort_et_c2.conf \
  snort_validation/et_open_c2/snort_et_c2_naive.conf && \
sed -i 's|^var ET_C2_RULES .*|var ET_C2_RULES /root/.hermes/c2-evasion-rl/snort_validation/et_open_c2/naive.rules|' \
  snort_validation/et_open_c2/snort_et_c2_naive.conf && \
grep -n 'ET_C2_RULES' snort_validation/et_open_c2/snort_et_c2_naive.conf
```

Kỳ vọng: đúng 2 dòng — `var ET_C2_RULES .../naive.rules` (đã đổi) và
`include $ET_C2_RULES`. Smoke test 1 flow (naive ≤ full alerts, sid là tập con):

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python - <<'PY'
import sys
from pathlib import Path
sys.path[:0] = ["ai_agent", "snort_validation"]
from eval_pipeline import client_ip_of, score_flow_real
from hidden_defender_env import HiddenDefenderEnv
env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
f = env._flows[0]; cip = client_ip_of(f["flow_id"])
full = score_flow_real(f["packets"], cip, 0, None)
naive = score_flow_real(f["packets"], cip, 0, None,
    conf=Path("snort_validation/et_open_c2/snort_et_c2_naive.conf"))
print("full:", full["n_alerts"], full["sids"], "| naive:", naive["n_alerts"], naive["sids"])
assert naive["n_alerts"] <= full["n_alerts"]
assert set(naive["sids"]) <= set(full["sids"])
print("SMOKE OK")
PY
```

Kỳ vọng: `SMOKE OK` (naive không nổ nhiều hơn full; sid là tập con).

### Task 3.3 — `--conf` cho sweep

`controls/ownership_ceiling_sweep.py`:

```python
    ap.add_argument("--conf", default=None,
                    help="snort conf path (default: ET Open full tier)")
...
    conf_kw = {"conf": Path(args.conf)} if args.conf else {}
...
        base = score_flow_real(pkts, cip, 0, None, ownership="both", **conf_kw)
        ...
        r = score_flow_real(pkts, cip, attempt_id, mech, ownership="both", **conf_kw)
...
out["conf"] = args.conf or "default (ET Open full)"
out["split"] = args.split   # (nếu chưa có)
```

Kèm test nhẹ (không Snort): `tests/test_sweep_conf_flag.py` — tách
`build_parser()` khỏi `main()` trong sweep (nếu parser đang inline) hoặc
import module rồi parse `["--split", "test", "--conf", "/x/y.conf"]` →
`args.conf == "/x/y.conf"`; RED → sửa → GREEN.

### Task 3.4 — Viết `/tmp/chain_both_v2.sh` (retrain với tên file V2, KHÔNG đè report cũ)

```bash
#!/bin/bash
set -u
SEED="$1"; EPOCHS="$2"
cd /root/.hermes/c2-evasion-rl || exit 1
TLOG="/tmp/trainb2_s${SEED}.log"; ELOG="/tmp/evalb2_s${SEED}.log"
: > "$ELOG"
echo "[chain] seed=$SEED epochs=$EPOCHS ownership=both v2 start $(date -Is)" >> "$ELOG"
.venv/bin/python ai_agent/train_hidden_defender_ppo.py \
  --real-snort --split train --n-flows 64 --max-epochs "$EPOCHS" \
  --ownership both --seed "$SEED" \
  --model-out "models/ppo_rs64_both_v2_s${SEED}.zip" > "$TLOG" 2>&1
RC=$?
echo "[chain] train exit=$RC $(date -Is)" >> "$ELOG"
[ $RC -ne 0 ] && exit $RC
.venv/bin/python ai_agent/eval_fixed_pipeline.py \
  --model "models/ppo_rs64_both_v2_s${SEED}.zip" --split test --ownership both \
  --out "snort_validation/reports/ppo_both_test_RS64_v2_s${SEED}.json" \
  --progress "snort_validation/reports/.eval_both_v2_s${SEED}_progress.jsonl" \
  >> "$ELOG" 2>&1
echo "[chain] EVAL_EXIT=$? $(date -Is)" >> "$ELOG"
```

(Kiểm tra `--model-out`/`--seed`/`--progress` là đúng tên flag hiện có:
`grep -n 'add_argument' ai_agent/train_hidden_defender_ppo.py ai_agent/eval_fixed_pipeline.py`
— nếu tên flag khác, sửa theo file, giữ nguyên cấu trúc.)

### Task 3.5 — Viết + BẮN Stage A (nền, tuần tự, notify khi xong)

**Chỉ bắn sau khi D1 cho phép (Nhánh A) hoặc user chọn "chạy đủ" (Nhánh B):**

```bash
cat > /tmp/stage_a_v2.sh <<'EOF'
#!/bin/bash
set -u
cd /root/.hermes/c2-evasion-rl || exit 1
L=/tmp/stage_a_v2.log
echo "[stageA] sweep full start $(date -Is)" >> $L
.venv/bin/python controls/ownership_ceiling_sweep.py --split test \
  --out snort_validation/reports/ceiling_ownership_both_v2.json >> $L 2>&1
echo "[stageA] sweep full exit=$? $(date -Is)" >> $L
echo "[stageA] sweep naive start $(date -Is)" >> $L
.venv/bin/python controls/ownership_ceiling_sweep.py --split test \
  --conf snort_validation/et_open_c2/snort_et_c2_naive.conf \
  --out snort_validation/reports/ceiling_naive_v2.json >> $L 2>&1
echo "[stageA] sweep naive exit=$? $(date -Is)" >> $L
for s in 7 1337 42; do bash /tmp/chain_both_v2.sh "$s" 40 || break; done
echo "[stageA] ALL DONE $(date -Is)" >> $L
EOF
chmod +x /tmp/stage_a_v2.sh
```

Bắn qua `terminal(command="/tmp/stage_a_v2.sh", background=True, notify=True)`
(Hermes notify báo khi xong; KHÔNG poll thủ công). Thời lượng dự kiến tuần tự:
sweep ~6.400s + sweep naive ~6.400s + 3 seed train/eval (vài giờ mỗi seed)
≈ **~8-12h**. Trong lúc chạy: tiếp tục Task 4.x/5.x (code độc lập), KHÔNG
chạy thêm job Snort song song để tránh tranh CPU.

### Commit 3 (code Phase 3, KHÔNG commit JSON reports cho tới Phase 6)

```bash
cd /root/.hermes/c2-evasion-rl && git add controls/make_naive_ruleset.py \
  controls/ownership_ceiling_sweep.py snort_validation/et_open_c2/snort_et_c2_naive.conf \
  tests/test_sweep_conf_flag.py && \
git commit -m "feat(P1): measured naive/expert ruleset tiers for the ceiling sweep
- make_naive_ruleset: baseline-fired SIDs -> naive.rules (Tier 1 of LCN25 axis)
- sweep --conf flag; naive conf variant of snort_et_c2.conf" && git log --oneline -1
```

## 7. Phase 4 (P3) — Learning curves / chi phí học từ log train

Không có TB events — train chỉ in ra log stdout, format đã xác minh trong
`/tmp/trainb_s42.log`:
`  [*] epoch  0: 64 queries, 0/64 flows valid this epoch (0.0%)`.

### Task 4.1 — `controls/learning_curves.py`

```python
#!/usr/bin/env python3
"""Parse PPO training logs -> CSV + bảng mean±std theo epoch (plan P3).

Line format (xác minh từ /tmp/trainb_s42.log):
  [*] epoch  12: 128 queries, 41/64 flows valid this epoch (64.1%)
"""
import argparse
import csv
import re
import sys
from pathlib import Path

EPOCH_RE = re.compile(
    r"\[\*\] epoch\s+(\d+):\s+(\d+) queries,\s+(\d+)/(\d+) flows valid this epoch \(([\d.]+)%\)")


def parse_train_log(text):
    """-> [{"epoch": int, "queries": int, "valid": int, "n": int, "pct": float}]"""
    return [
        {"epoch": int(m.group(1)), "queries": int(m.group(2)),
         "valid": int(m.group(3)), "n": int(m.group(4)), "pct": float(m.group(5))}
        for m in EPOCH_RE.finditer(text)
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="7,1337,42")
    ap.add_argument("--v2", action="store_true", default=True,
                    help="read /tmp/trainb2_s*.log (fall back to trainb_s*)")
    ap.add_argument("--out", default="snort_validation/reports/learning_curves_v2.csv")
    args = ap.parse_args()

    rows = []
    for seed in args.seeds.split(","):
        for prefix in ("trainb2", "trainb"):
            p = Path(f"/tmp/{prefix}_s{seed}.log")
            if p.exists():
                break
        else:
            print(f"[skip] no log for seed {seed}", file=sys.stderr)
            continue
        for r in parse_train_log(p.read_text(errors="ignore")):
            rows.append({"seed": seed, **r})

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["seed", "epoch", "queries", "valid", "n", "pct"])
        w.writeheader()
        w.writerows(rows)

    # mean±std pct cross-seed theo epoch
    by_ep = {}
    for r in rows:
        by_ep.setdefault(r["epoch"], []).append(r["pct"])
    print("| epoch | mean pct | std | seeds |")
    print("|---|---|---|---|")
    for ep in sorted(by_ep):
        v = by_ep[ep]
        mean = sum(v) / len(v)
        std = (sum((x - mean) ** 2 for x in v) / max(len(v) - 1, 1)) ** 0.5
        print(f"| {ep} | {mean:.1f} | {std:.1f} | {len(v)} |")
    print(f"\nCSV -> {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
```

Dev trên log CŨ trước (chưa có v2): `--out /tmp/curves_dev.csv` → kỳ vọng
CSV ≥ 3×(số epoch) rows, bảng in ra 41 dòng (epoch 0..40).

### Task 4.2 — Test

`tests/test_learning_curves.py`: text fixture 2 dòng epoch (1 dòng có extra
spaces) → `parse_train_log` trả đúng 2 dict; dòng sai format → bỏ qua không crash.
RED (chưa có module) → GREEN.

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest \
  tests/test_learning_curves.py -q 2>&1 | tail -3
```

### Commit 4

```bash
cd /root/.hermes/c2-evasion-rl && git add controls/learning_curves.py \
  tests/test_learning_curves.py && \
git commit -m "feat(P3): learning-curve extraction from PPO training logs" && \
git log --oneline -1
```

## 8. Phase 5 (P4) — Cross-engine spot-check: Suricata vs Snort

Mục tiêu: kiểm chứng "split evaded" có phải đặc thù của config Snort này
không. **Bước 5.1 fail thì đánh dấu SKIP có ghi chú, không cưỡng ép.**

### Task 5.1 — Cài + smoke

```bash
suricata -V 2>/dev/null || (apt-get update -qq && apt-get install -y -qq suricata)
suricata -V
```

Kiểm tra ruleset compat (ET Open Snort-syntax có chạy được dưới Suricata không):

```bash
cd /root/.hermes/c2-evasion-rl && suricata -T -c /etc/suricata/suricata.yaml \
  -S snort_validation/et_open_c2/et_open_c2.rules 2>&1 | tail -8
```

Kỳ vọng: dòng `Suricata: rules successfully loaded` (hoặc warning nhỏ, exit 0).
Nếu exit != 0 → thử với `naive.rules` thay `et_open_c2.rules`. Vẫn fail →
**SKIP P5**: ghi vào THREAT_MODEL mục "Cross-engine check: not run (ruleset
syntax incompatible / install unavailable)", commit ghi chú, không bịa kết quả.

### Task 5.2 — `controls/cross_engine_check.py`

```python
#!/usr/bin/env python3
"""Cross-engine spot-check (plan P4): dựng pcap baseline + split bằng ĐÚNG
pipeline (mutate_client_only + translate_source + wrpcap), chạy Suricata,
so evaded verdict với Snort (đọc từ sweep v2 JSON nếu có)."""
import argparse, json, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]
from scapy.all import wrpcap
from eval_pipeline import client_ip_of, mutate_client_only, translate_source
from hidden_defender_env import HiddenDefenderEnv


def suricata_alerts(pcap, rules, workdir) -> int:
    logdir = Path(workdir) / "fast"
    logdir.mkdir(parents=True, exist_ok=True)
    cmd = ["suricata", "-c", "/etc/suricata/suricata.yaml", "-r", str(pcap),
           "-S", str(rules), "-l", str(logdir), "--runmode", "single"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"suricata failed: {proc.stderr[-800:]}")
    fast = logdir / "fast.log"
    if not fast.exists():
        return 0
    return sum(1 for line in fast.read_text(errors="ignore").splitlines()
               if line.strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=str(ROOT / "snort_validation/et_open_c2/naive.rules"))
    ap.add_argument("--mechs", default="split8,split16,split24")
    ap.add_argument("--limit", type=int, default=0, help="0 = all test flows")
    ap.add_argument("--out", default=str(ROOT / "snort_validation/reports/cross_engine_snort_vs_suricata.json"))
    args = ap.parse_args()

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    mechs = [m for m in args.mechs.split(",") if m]
    cells = []
    with tempfile.TemporaryDirectory(prefix="xsurf_") as td:
        flows = env._flows[: args.limit] if args.limit else env._flows
        for fi, f in enumerate(flows):
            cip = client_ip_of(f["flow_id"])
            for mech in [None] + mechs:
                pkts = (list(f["packets"]) if mech is None
                        else mutate_client_only(f["packets"], mech, cip))
                pkts = translate_source(pkts, cip, attempt_id=fi % 250)
                name = f"{fi:02d}_{'base' if mech is None else mech}.pcap"
                pcap = Path(td) / name
                wrpcap(str(pcap), pkts)
                n = suricata_alerts(pcap, args.rules, td)
                cells.append({"flow_id": f["flow_id"], "mech": mech or "none",
                              "suricata_alerts": n, "evaded": n == 0})
    out = Path(args.out)
    out.write_text(json.dumps({"engine": "suricata", "rules": args.rules,
                               "cells": cells}, indent=1))
    n_base = sum(1 for c in cells if c["mech"] == "none" and c["evaded"])
    print(f"cells={len(cells)} baseline-evaded-by-suricata={n_base} -> {out}")
    print("NOTE: baseline nên evaded=0 (nếu baseline đã 0 alert thì ruleset sai)")

if __name__ == "__main__":
    main()
```

Chạy nhỏ trước (2 flow × 4 ô ≈ vài chục giây), rồi full:

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/cross_engine_check.py --limit 2
# kỳ vọng: in "cells=8 baseline-evaded-by-suricata=0" (baseline của 2 flow
# phải nổ alert dưới Suricata) rồi chạy full 40 flow:
.venv/bin/python controls/cross_engine_check.py
```

Đối chiếu (Phase 6): mỗi ô `mech != none` so `evaded` với ô tương ứng trong
`ceiling_ownership_both_v2.json` → % đồng thuận in vào THREAT_MODEL.

### Commit 5

```bash
cd /root/.hermes/c2-evasion-rl && git add controls/cross_engine_check.py && \
git commit -m "feat(P4): Suricata cross-engine spot-check for split mechs" && \
git log --oneline -1
```

## 9. Phase 6 — Khi Stage A xong: phân tích, docs, đối soát cuối

### Task 6.1 — Confirm Stage A sạch

```bash
cd /root/.hermes/c2-evasion-rl && tail -6 /tmp/stage_a_v2.log && ls -la \
  snort_validation/reports/ceiling_ownership_both_v2.json \
  snort_validation/reports/ceiling_naive_v2.json \
  snort_validation/reports/ppo_both_test_RS64_v2_s*.json
```

Kỳ vọng: dòng `[stageA] ALL DONE`, 2 sweep JSON + 3 eval JSON tồn tại,
mỗi file có `"n_flows": 40`. Nếu 1 job exit != 0 → đọc log tương ứng
(`/tmp/stage_a_v2.log`, `/tmp/trainb2_s*.log`, `/tmp/evalb2_s*.log`), sửa
nguyên nhân, chạy lại JOB ĐÓ (không cần chạy lại cả chain).

### Task 6.2 — Bảng stratified + tier matrix

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python controls/alert_stratification.py \
  --sweep snort_validation/reports/ceiling_ownership_both_v2.json
```

Tier matrix (in 2 tầng naive vs expert cho từng mech, từ 2 sweep JSON):

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python - <<'PY'
import json
from pathlib import Path
def load(p):
    d = json.loads(Path(p).read_text())
    agg = {}
    for r in d["rows"]:
        a = agg.setdefault(r["mech"], {"flows": 0, "evaded": 0, "valid": 0})
        a["flows"] += 1; a["evaded"] += bool(r["evaded"]); a["valid"] += bool(r.get("valid_evasion"))
    return agg
full = load("snort_validation/reports/ceiling_ownership_both_v2.json")
naive = load("snort_validation/reports/ceiling_naive_v2.json")
print("| mech | naive evaded/valid | expert evaded/valid |")
print("|---|---|---|")
for m in sorted(set(full) | set(naive)):
    n, f = naive.get(m, {}), full.get(m, {})
    print(f"| {m} | {n.get('evaded',0)}/{n.get('valid',0)} | "
          f"{f.get('evaded',0)}/{f.get('valid',0)} |")
PY
```

Curves: `.venv/bin/python controls/learning_curves.py --out snort_validation/reports/learning_curves_v2.csv`.

Cross-engine: so `evaded` từng ô Suricata vs Snort → % đồng thuận.

### Task 6.3 — Patch `docs/THREAT_MODEL.md` (chỉ số ĐÃ ĐO, không dự đoán)

Mục mới / cập nhật:
1. **Wire deliverability**: định nghĩa bar 2 tầng (stream bytes + deliverable),
   ghi rõ con số TRƯỚC sửa (sinh từ fragment không deliverable) bị thay bằng
   con số v2; ghi probe D1 (2 nhánh, nhánh nào xảy ra).
2. **Ceiling v2** (ownership both): thay/ghép bảng bằng
   `ceiling_ownership_both_v2.json`; ghi nhãn "giới hạn dưới = client, giới
   hạn trên = both" như hiện tại.
3. **Stratified by classtype**: bảng từ Task 6.2 (tách trojan-activity vs
   policy-violation) — đây là câu trả lời "hộp số" cho LCN25 P2.
4. **Ruleset tiers**: bảng naive vs expert (Task 6.2) + ghi "naive = tập rule
   nổ baseline, đo được".
5. **Learning curves**: đường dẫn CSV + 3 dòng mean pct epoch 0/mid/final.
6. **Cross-engine**: kết quả Suricata hoặc ghi rõ SKIP kèm lý do.
7. Ghi chú TLS scope (corpus HTTP cleartext — theo LCN25 limitation).

### Task 6.4 — Full suite + commit docs/reports cuối

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests -q 2>&1 | tail -4
```

Kỳ vọng: **0 failed**, passed ≥ 121. Sau đó:

```bash
cd /root/.hermes/c2-evasion-rl && git add docs/THREAT_MODEL.md \
  snort_validation/reports/ceiling_ownership_both_v2.json \
  snort_validation/reports/ceiling_naive_v2.json \
  snort_validation/reports/ppo_both_test_RS64_v2_s*.json \
  snort_validation/reports/learning_curves_v2.csv \
  snort_validation/reports/cross_engine_snort_vs_suricata.json \
  snort_validation/reports/baseline_sids_test.json 2>/dev/null; \
git commit -m "reports(P0-P4): corrected ceiling sweep, 3-seed retrain, tiers,
severity stratification, learning curves, cross-engine check" && git log --oneline -6
```

### Task 6.5 — Reply cuối cho user (tiếng Việt, có số thật)

Báo cáo: (a) con số v2 của trần + 3 seed SO VỚI con số cũ + nguyên nhân
(fragment không deliverable đã bị bar mới chặn/phát hiện thế nào — trích probe
D1), (b) bảng stratified classtype, (c) bảng tier naive/expert, (d) curves +
cross-engine, (e) các việc chưa làm (open questions dưới đây). Không nói
"100%" nếu số v2 không phải 100%.

## 10. Tests / Validation — bảng đối soát

| # | Task | Lệnh | Kỳ vọng |
|---|---|---|---|
| 1 | 1.2 RED | `pytest tests/test_wire_deliverability.py -q` | ≥ 5 failed |
| 2 | 1.4 compile | `python -c "import ..."` | `imports OK` |
| 3 | 1.6 GREEN | `pytest tests/test_wire_deliverability.py tests/test_fragment_ops.py tests/test_ownership_model.py tests/test_evaluation_fixes.py -q` | 0 failed |
| 4 | 1.7 full | `pytest tests -q` | ≥ 121 passed (109 cũ + 8 mới), 0 failed |
| 5 | 1.8 probe D1 | `python /tmp/probe_recut.py` | nhánh A hoặc B → xử lý theo đúng nhánh |
| 6 | 2.6 strat | `pytest tests/test_alert_stratification.py -q` | passed |
| 7 | 2.1-2.2 không đổi hành vi | `pytest tests/test_evaluation_fixes.py tests/test_eval_cli.py tests/test_semantics_bar_agreement.py -q` | passed |
| 8 | 3.1 naive rules | `python controls/make_naive_ruleset.py` | `kept ≥ 4/21374` |
| 9 | 3.2 smoke conf | smoke 1 flow ở Task 3.2 | `SMOKE OK` |
| 10 | 3.3 conf flag | `pytest tests/test_sweep_conf_flag.py -q` | passed |
| 11 | 4.x curves dev | `python controls/learning_curves.py --out /tmp/curves_dev.csv` | CSV rows ≥ 3 epoch-count |
| 12 | 5.1 suricata | `suricata -T ...` | exit 0 hoặc SKIP có ghi chú |
| 13 | 5.2 cross-eng limit | `python controls/cross_engine_check.py --limit 2` | `cells=8 baseline-evaded=0` |
| 14 | Stage A | `tail /tmp/stage_a_v2.log` | `ALL DONE`, 5 JSON tồn tại |
| 15 | 6.4 final | `pytest tests -q` | 0 failed, passed ≥ 121 |

## 11. Risks, tradeoffs, open questions

- **R1 (lớn nhất)**: split CÙNG BYTES có thể KHÔNG còn evaded khi fragment
  đúng chuẩn (frag3 `policy first` dựng lại được stream → content rule nổ
  lại). Đây là kết quả trung thực phải chấp nhận — cổng D1 ở Task 1.8 bắt
  phải dừng hỏi user trước khi retrain. **Cấm** sửa bar/probe để giữ 100%.
- **R2**: test cũ encode geometry fragment cũ sẽ đỏ → chỉ sửa assert mô tả
  đúng hình học mới, ghi lý do trong commit; không nới bar.
- **R3**: Snort tính lại checksum/len khi wrpcap — fragment mới dựng bằng
  scapy `chksum=None` nên được tính lại; nếu probe thấy Snort drop vì checksum
  thì check lại `fix_checksums`/`translate_source`.
- **R4**: tier naive phụ thuộc tập sid baseline; sid baseline KHÔNG đổi vì
  baseline không mutate → ổn định giữa các lần chạy; nhưng nếu R1 làm probe
  fail thì naive.rules vẫn đúng (baseline không ảnh hưởng).
- **R5**: Suricata/ET syntax có thể không tương thích → SKIP có ghi chú
  (không bịa), chấp nhận P4 unfinished.
- **R6**: Stage A ~8-12h CPU tuần tự; KHÔNG chạy job Snort song song khác;
  notify khi xong, không poll.
- **R7**: replica (`real_snort=False`) có thể nhìn cấu trúc fragment →
  `test_mechanisms_ab:143` (best=split8) và `test_policy_diversity:84`
  (reward split8) có thể đổi kết quả → điều tra, báo cáo, không sửa blind.
- **R8**: `int(ip.proto)` có thể là `None` với packet dựng tay → đã có guard
  trong code Task 1.3.
- **R9**: overlap8-TCP trở thành "không áp dụng" (hợp lý: không tồn tại hình
  học đúng với TH=20) → số ô overlap8 thay đổi so với sweep cũ — dự kiến,
  ghi vào THREAT_MODEL.
- **R10**: curve P3 đọc stdout log → format đổi ở train script là parser vỡ;
  regex có test fixture bắt hồi quy format.

**Open questions (KHÔNG làm trong plan này, cần user quyết):**

1. **Chính sách overlap tại endpoint thật** (first-fragment-wins hay
   last-wins?): nếu endpoint = last-wins thì overlap-UDP có thể trở thành
   evader HỢP LỆ (IDS policy-first thấy decoy, endpoint nhận real) — nhưng
   bar stream hiện tại (join không policy-aware) đang chặn nó. Muốn mở thì
   phải đo endpoint policy trước (netns + scapy), rồi đổi bar có chủ đích —
   một quyết định threat-model riêng.
2. **Train trên tier naive / eval matrix** (LCN25 huấn luyện riêng naive vs
   expert): tốn ~8h/ma trận nữa → chỉ làm nếu user đồng ý sau khi thấy số v2.
3. **Timing / size / port-hop actions** (P1 từ câu hỏi trước): thêm vào action
   space = 1 task riêng, không thuộc plan trung thực này.
