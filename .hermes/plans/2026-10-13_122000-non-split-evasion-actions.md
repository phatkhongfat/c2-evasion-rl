# P14 — Action không-split: nâng coverage C2 bằng cơ chế protocol-legitimate

> Plan cho implementer **zero-context**. Mọi đường dẫn là tương đối so với
> repo `/root/.hermes/c2-evasion-rl` (branch `packet-level-rl`). Đọc xong
> mục "Bối cảnh" là làm được không cần hỏi.

## Goal

Nâng coverage evasion **không dùng họ split/fragmentation** trên đúng
mẫu số threat-model C2 đã đóng băng, bằng các cơ chế hợp lệ ngữ nghĩa mới
(sửa HTTP request theo cách handler thật vẫn đọc được), đo bằng Snort thật
dưới cả hai bar — không hạ bar, không đổi mẫu số sau khi đo.

## Bối cảnh — số liệu đã đo (KHÔNG phải giả định)

Khung đo: `controls/ownership_ceiling_sweep.py` ghi report dạng cell
(`flow_id, mech, baseline_alert, evaded, semantics_ok, valid_evasion,
valid_evasion_endpoint, sids, baseline_sids`); scorer là Snort 2.9.20 thật
(`snort_validation/eval_pipeline.py:score_flow_real`). Hai bar:
`valid_evasion` (byte-equality 2 stream) và `valid_evasion_endpoint`
(`endpoint_model.parse_command` — handler thật còn đọc được lệnh).

### Corpus cũ (`snort_validation/reports/hidden_defender_corpus.pkl`, test = 40 flow)

Report gốc: `snort_validation/reports/ceiling_v4_both_test_dualbar.json`
(15 mech × 40 flow, conf 21.374 rule) và `ceiling_v6_case_fullrules_dualbar.json`
(3 mech × 40 flow, có `http_header_case`).

Đo lại từ report (2026-10-13, chế độ loại split, endpoint bar):

| nhóm | flow | SID baseline | trong threat model C2? |
|---|---:|---|---|
| neris binary framing | 24 | `2008581/2008583/2008585` (BitTorrent DHT, classtype `policy-violation`) | **KHÔNG** — đã đóng băng loại P2P khỏi mẫu số (P12) |
| http framing, case-valid | 14 | `2012627` FakeAV | có |
| http framing, case **fail endpoint** | 2 | `2012627` FakeAV | có — **mục tiêu Phase 1** |

→ **Mẫu số C2 đóng băng = 16 flow; coverage không-split hiện tại = 14/16.**
Hai flow fail:
`botnet-capture-20110811-neris|147.32.84.165:3531->184.82.147.251:80|tcp` và
`...:3039->184.82.148.43:80|tcp`. Với `http_header_case` cả hai **evaded=True
nhưng endpoint fail** (lệnh không còn đọc được) — cần chẩn đoán, không đoán.

### Corpus mở rộng (`snort_validation/reports/corpus_p13_extended.pkl`, test = 120 flow, conf `rulesets/p13/snort_et3000.conf` 52.454 rule)

- 115/120 flow có baseline alert (report `snort_validation/reports/p13_v7_noop.json`).
- 5 flow có HTTP request thật (`is_http_request`), đã đo với
  `noop/http_header_case/split8` (report `snort_validation/reports/p13_v8_case_extended.json`):
  4 flow dính `2012533` (Virut.BN check-in), 1 flow dính `2018959`
  (PE download, classtype `policy-violation`, hướng `to_client`).
  `http_header_case` = **0/5**, `split8` = 5/5 cả hai bar.
- 110 flow còn lại chưa phân loại theo classtype — **Phase 0 làm việc đó**.

### Văn bản rule liên quan (đã dump từ `rulesets/p13/et_open_3000.rules`)

```
sid:2012533 (Virut): content:"GET "; depth:4; content:"list.php?c="; within:32;
  content:"&v="; distance:0; content:"&t="; distance:0;
  pcre:"/c\x3d[0-9A-F]{100}/i";
```
→ Chuỗi literal `list.php?c=` là mắt xích yếu: **chèn một query param lạ
trước `c=`** (vd `list.php?x=0&c=...`) phá content mà mọi query parser chuẩn
vẫn đọc đúng `c`, `v`, `t`. KHÔNG cần giả định handler percent-decode.

```
sid:2018959 (PE download): $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET; file_data;
  content:"MZ"; ... classtype:policy-violation
```
→ Hướng **to_client**, match trên bytes file thật — không có biến đổi phía
client nào giữ ngữ nghĩa. Loại khỏi mẫu số C2 theo tiền lệ policy-violation
(Quyết định đóng băng của user với DHT P2P), hoặc chấp nhận chỉ-split.

```
sid:2012627 (FakeAV): 4 content distance:0, đã bị http_header_case phá
  (14/16 endpoint-valid) — 2 flow fail cần chẩn đoán Phase 1.
```

### Điểm nghẽn endpoint model (đọc `snort_validation/endpoint_model.py`)

`_parse_http` trả về **nguyên văn URI** (`parts[1]`) cho GET không body.
Chèn param hay percent-encode sẽ đổi URI thô → endpoint bar hiện tại FAIL
dù handler thật vẫn đọc đúng lệnh. Vì vậy Phase 2 cần **bar mở rộng có
citation** (D5 bên dưới), theo đúng tiền lệ hai-bar: thêm biến thể phân loại
mới, KHÔNG sửa bar cũ, báo cáo cả ba.

## Quyết định đóng băng TRƯỚC khi đo (ghi vào `docs/action_space_policy.md`, mục D4–D6)

- **D4 (mẫu số theo classtype):** flow thuộc mẫu số C2 iff `baseline_sids`
  chứa ≥1 SID có `classtype` ∈ {trojan-activity, malware, ...} — loại
  `policy-violation`, scan/recon (`attempted-recon`, `bad-unknown` dạng
  ET SCAN), và bộ ba P2P đã đóng băng `{2008581,2008583,2008585}`.
  classtype là metadata tác giả rule, cố định trước mọi phép đo → không phải
  dời cầu môn. **Luôn báo cáo cả số thô (x/120) lẫn số threat-model (x/N).**
- **D5 (endpoint bar v2 cho HTTP GET, CHỈ khi citation đạt):** lệnh của GET
  không body = **tập key→value của query string sau khi parse chuẩn**
  (split `&`, split `=` lần đầu, percent-decode cả key lẫn value, bỏ qua
  param không nằm trong tập key gốc). Căn cứ: RFC 3986 §2.1–2.4; hành vi
  `parse_str`/`$_GET` của PHP (handler của `list.php`). Mọi quote phải qua
  ledger `~/.hermes/skills/research/grounded-citations` trước khi implement.
  Bar cũ (`valid_evasion_endpoint`) **giữ nguyên**; bar mới tên
  `valid_evasion_endpoint_q` — report ghi cả hai.
- **D6 (cơ chế mới không vào env vội):** theo tiền lệ `http_header_case` —
  mech mới chỉ sống trong `eval_pipeline.mutate_client_only` + mirror trong
  `hidden_defender_env.apply_mech` (Fix 3 chống drift), KHÔNG đổi
  `Discrete(14)` cho tới khi có kết quả sweep.

## Kiến trúc / cách tiếp cận

Ba mũi, xếp theo độ chắc: (1) chẩn đoán + sửa 2 flow FakeAV mà
`http_header_case` làm hỏng endpoint (nhiều khả năng do header trải nhiều
packet hoặc `_lower_field_names` chạm phần lệnh) → 16/16 trên corpus cũ;
(2) cơ chế mới `query_param_prepend` phá content-chain của `2012533` bằng
param vô hại (+4 byte, không cần decode assumption) → phủ 4/5 flow C2 của
corpus mở rộng; (3) `uri_value_percent` làm dự phòng (cần D5) nếu (2) hụt.
Mọi cơ chế đi qua đúng vòng TDD + probe Snort nhỏ trước + sweep đầy sau.

---

## Phase 0 — Trinh sát read-only + đóng băng quyết định (không tốn Snort)

### T0.1 Phân loại classtype cho 115 flow alert của corpus mở rộng

```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python - <<'PY'
import json, re, pathlib, collections
# SID -> classtype từ ruleset (metadata tác giả, cố định trước khi đo)
ct = {}
for ln in pathlib.Path('rulesets/p13/et_open_3000.rules').open(errors='ignore'):
    m = re.search(r'sid:(\d+);', ln)
    if m:
        c = re.search(r'classtype:([^;]+);', ln)
        ct[m.group(1)] = c.group(1) if c else '?'
d = json.load(open('snort_validation/reports/p13_v7_noop.json'))
inscope, out = [], collections.Counter()
for c in d['cells']:
    if not c['baseline_alert']: continue
    kinds = {ct.get(str(s), '?') for s in c['baseline_sids']}
    mal = {k for k in kinds if k in ('trojan-activity','malware-cnc',
           'trojan', 'malware')}
    (inscope.append((c['flow_id'], sorted(c['baseline_sids'])))
     if mal else out.update(kinds))
print(f"flow TRONG mau so C2: {len(inscope)}")
for f, s in inscope: print("  ", f, s)
print("classtype cua flow LOAI:", dict(out))
PY
```
**Output kỳ vọng:** danh sách flow in-scope (≥1 SID trojan/malware) + bảng
classtype bị loại. Ghi kết quả vào `docs/p14_denominator.md` (tạo mới).
Số này **đóng băng mẫu số v8** trước khi chạy bất kỳ sweep cơ chế mới nào.

### T0.2 Chẩn đoán 2 flow FakeAV fail-endpoint với `http_header_case`

```bash
.venv/bin/python - <<'PY'
import json, pickle, sys
sys.path.insert(0,'snort_validation'); sys.path.insert(0,'ai_agent')
from eval_pipeline import client_ip_of, mutate_client_only
from endpoint_model import parse_command
d = pickle.load(open('snort_validation/reports/hidden_defender_corpus.pkl','rb'))
targets = {
 'botnet-capture-20110811-neris|147.32.84.165:3531->184.82.147.251:80|tcp',
 'botnet-capture-20110811-neris|147.32.84.165:3039->184.82.148.43:80|tcp'}
for f in d['test']:
    if f['flow_id'] not in targets: continue
    cip = client_ip_of(f['flow_id'])
    orig = b"".join(bytes(p.payload.payload) if hasattr(p,'payload') else b""
                    for p in [])  # KHONG dung; lay payload qua Raw:
    from scapy.all import IP, Raw
    def joined(pkts):
        return b"".join(bytes(p[Raw].load) for p in pkts
                        if IP in p and Raw in p and p[IP].src == cip)
    mut = mutate_client_only(f['packets'], 'http_header_case', cip,
                             ownership='both')
    c0 = parse_command(joined(f['packets']), 'http')
    c1 = parse_command(joined(mut), 'http')
    print(f['flow_id'])
    print("  cmd orig:", c0[:80] if c0 else c0)
    print("  cmd mut :", c1[:80] if c1 else c1)
    print("  equal:", c0 == c1)
PY
```
**Kỳ vọng:** in ra `cmd orig` vs `cmd mut` khác nhau ở đâu. Ba giả thuyết,
mỗi cái dẫn tới nhánh sửa khác nhau ở T1:
- (a) `c1 = None` → mutation làm mất `\r\n\r\n` hoặc request line hỏng
  (header trải nhiều packet, cơ chế chỉ sửa packet đầu) → **T1 nhánh A**;
- (b) `c1` = body bị đổi → `_lower_field_names` chạm body hoặc field không
  phải header → **T1 nhánh B**;
- (c) `c0 = None` → baseline vốn không parse được → flow này KHÔNG thuộc
  mẫu số endpoint từ đầu; ghi nhận, không sửa gì (báo cáo trung thực).

### T0.3 Dump toàn văn rule cho mọi SID in-scope tìm được ở T0.1

```bash
for s in <DANH_SACH_SID_TU_T0.1>; do
  grep -h "sid:$s;" rulesets/p13/et_open_3000.rules | cut -c1-500; echo
done
```
Với mỗi rule ghi 1 dòng vào `docs/p14_denominator.md`: SID | classtype |
buffer (raw/`file_data`/`http_*`) | hướng | **slack khả dĩ** (literal nào phá
được mà giữ ngữ nghĩa) hoặc `KHÔNG-SLACK` (bytes protocol-fixed, vd TLS
handshake của `2014635`). **Không hứa cơ chế cho rule chưa xác nhận slack**
(bài học P8: verify REACHABLE trước khi hứa).

### T0.4 Đóng băng D4–D6

Append vào `docs/action_space_policy.md` (file đã frozen D1–D3 — thêm mục
"D4–D6 (P14, frozen 2026-10-13)" kèm số liệu T0.1 làm căn cứ). Commit:
```bash
git add docs/p14_denominator.md docs/action_space_policy.md
git commit -m "docs(P14.0): freeze denominator by classtype + D4-D6 before measurement"
```

---

## Phase 1 — Sửa `http_header_case` cho 2 flow fail (chỉ khi T0.2 ra nhánh A hoặc B)

### T1.1 RED: test tái hiện lỗi

Tạo `tests/test_case_multipacket.py`:

```python
"""http_header_case must preserve the endpoint command when the header
block spans several TCP segments, and must never touch the body."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))
from scapy.all import Ether, IP, TCP, Raw
from eval_pipeline import client_ip_of, mutate_client_only
from endpoint_model import parse_command

def _flow_two_segment_headers():
    # header block bị cắt giữa packet 1 va 2 (khong co \r\n\r\n trong pkt 1)
    req = (b"GET /a.php?x=1 HTTP/1.1\r\nUser-Agent: Mozilla/4.0\r\n"
           b"Host: h\r\n\r\n")
    cut = req.index(b"Host")
    mk = lambda load, seq: Ether()/IP(src="147.32.84.165", dst="8.8.8.8")/ \
        TCP(sport=1024, dport=80, seq=seq, flags="PA")/Raw(load=load)
    pkts = [mk(req[:cut], 1), mk(req[cut:], 1 + len(req[:cut]))]
    return {"flow_id": "cap|147.32.84.165:1024->8.8.8.8:80|tcp",
            "packets": pkts, "framing": "http"}

def test_case_multipacket_preserves_command():
    f = _flow_two_segment_headers()
    cip = client_ip_of(f["flow_id"])
    mut = mutate_client_only(f["packets"], "http_header_case", cip,
                             ownership="both")
    joined = lambda pkts: b"".join(bytes(p[Raw].load) for p in pkts
                                   if IP in p and Raw in p
                                   and p[IP].src == cip)
    c0 = parse_command(joined(f["packets"]), "http")
    c1 = parse_command(joined(mut), "http")
    assert c0 is not None
    assert c1 == c0, (c0, c1)          # lenh phai con nguyen
    assert joined(mut) != joined(f["packets"])  # mutation phai doi byte
```

```bash
.venv/bin/python -m pytest tests/test_case_multipacket.py -x -q
```
**Kỳ vọng RED:** FAIL ở `assert c1 == c0` hoặc `c1 is None` (nếu cơ chế
hiện tại bỏ qua packet không có `\r\n\r\n` thì `c1 == c0` và FAIL ở assert
cuối — cả hai đều là RED hợp lệ, ghi lại kiểu nào).

### T1.2 GREEN: mutation mức stream

Trong `snort_validation/eval_pipeline.py`, nhánh `elif mech ==
"http_header_case":` (khoảng dòng 230) hiện đi từng packet. Sửa thành:
nối payload các packet client theo thứ tự → `_lower_field_names` một lần
trên head của stream → chia lại **đúng ranh giới độ dài cũ** (byte-bar
không quan tâm vị trí cắt, chỉ cần tổng stream bằng; endpoint đọc stream
nối). Giữ nguyên guard `is_http_request`. Code tối thiểu:

```python
    elif mech == "http_header_case":
        raws = [(i, bytes(out[i][Raw].load)) for i in payload_idx
                if Raw in out[i] or as_raw(out[i]) is not None]
        # payload_idx da loc packet client co payload; as_raw collapse an toan
        stream = b"".join(r for _, r in raws)
        if is_http_request(stream):
            head, sep, body = stream.partition(b"\r\n\r\n")
            if sep:
                new = _lower_field_names(head) + b"\r\n\r\n" + body
                pos = 0
                for i, old in raws:
                    out[i][Raw].load = new[pos:pos + len(old)]
                    pos += len(old)
```
Mirror đúng logic đó vào `ai_agent/hidden_defender_env.py` nhánh
`http_header_case` trong `apply_mech` (khoảng dòng 339 — Fix 3: hai bản phải
byte-identical; xem test T7 cũ trong `tests/` làm mẫu byte-identity).

```bash
.venv/bin/python -m pytest tests/test_case_multipacket.py tests/test_http_header_case.py -x -q
```
**Kỳ vọng GREEN:** tất cả pass (test cũ của case không được vỡ).

### T1.3 Probe Snort thật trên đúng 2 flow + 4 flow chứng kiến

Viết `controls/probe_case_fix.py`: dùng `score_flow_real` (import như
`controls/p13_case_extended.py` — copy pattern file đó) chấm
`http_header_case` trên: 2 flow fail cũ + 4 flow case-valid cũ (chống hồi
quy), conf `snort_validation/et_open_c2/snort_et_c2.conf`. 6 flow × 1 mech
× ~15s (conf 21k nhanh hơn 52k) ≈ **2 phút**.

**Gate (ghi TRƯỚC, không đổi sau):** 2 flow fail → `valid_evasion_endpoint
= True`; 4 flow chứng kiến → vẫn True. Fail gate → dừng, ghi negative vào
plan, KHÔNG nới guard.

Commit: `git commit -m "fix(P14.1): stream-level http_header_case -- headers spanning segments"`

---

## Phase 2 — Cơ chế mới `query_param_prepend` (mục tiêu: 4 flow `2012533`)

### T2.1 RED: `tests/test_query_param_prepend.py`

```python
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "snort_validation"))
sys.path.insert(0, str(ROOT / "ai_agent"))
from scapy.all import Ether, IP, TCP, Raw
from eval_pipeline import client_ip_of, mutate_client_only

REQ = (b"GET /list.php?c=" + b"A1" * 50 + b"&v=2&t=0.89 HTTP/1.0\r\n"
       b"User-Agent: M\r\nHost: h\r\n\r\n")

def _flow():
    p = Ether()/IP(src="147.32.84.165", dst="8.8.8.8")/ \
        TCP(sport=1, dport=80, flags="PA")/Raw(load=REQ)
    return {"flow_id": "cap|147.32.84.165:1->8.8.8.8:80|tcp",
            "packets": [p], "framing": "http"}

def _client_load(pkts):
    return b"".join(bytes(p[Raw].load) for p in pkts if Raw in p
                    and p[IP].src == "147.32.84.165")

def test_param_prepend_breaks_literal_chain_only():
    f = _flow()
    mut = mutate_client_only(f["packets"], "query_param_prepend",
                             client_ip_of(f["flow_id"]), ownership="both")
    new = _client_load(mut)
    assert b"list.php?c=" not in new          # content cua 2012533 bi pha
    assert b"c=" + b"A1" * 50 in new          # gia tri c con nguyen ven
    assert b"&v=2&t=0.89" in new              # cac param khac con nguyen
    assert new.startswith(b"GET /list.php?x=0&c=")  # param chen dau, +4B

def test_param_prepend_skips_non_query_requests():
    f = _flow()
    from scapy.all import Raw as R
    f["packets"][0][R].load = REQ.replace(b"?c=", b"/c/", 1)  # khong query
    mut = mutate_client_only(f["packets"], "query_param_prepend",
                             client_ip_of(f["flow_id"]), ownership="both")
    assert _client_load(mut) == f["packets"][0][R].load  # khong doi
```

```bash
.venv/bin/python -m pytest tests/test_query_param_prepend.py -x -q
```
**Kỳ vọng RED:** 2 fail (mech chưa tồn tại — mutation trả nguyên bản).

### T2.2 GREEN: implement trong `eval_pipeline.mutate_client_only`

Thêm nhánh trước `elif mech == "length_wrapper":`:

```python
    elif mech == "query_param_prepend":
        # Chen mot param vo hai ngay sau '?' cua request line: pha cac
        # content-chain neo vao literal "<path>?<firstkey>=" (vd sid:2012533
        # "list.php?c=") trong khi moi query parser chuan van doc dung
        # key/value (split '&' roi '=' -- RFC 3986, PHP parse_str).
        # Chi ap dung cho request line; body khong dung. +4 byte.
        for i in payload_idx:
            out[i] = as_raw(out[i])
            raw = bytes(out[i][Raw].load)
            if not is_http_request(raw):
                continue
            head, sep, rest = raw.partition(b"\r\n")
            if not sep:
                continue
            parts = head.split(b" ")
            if len(parts) < 2 or b"?" not in parts[1]:
                continue
            uri = parts[1]
            q = uri.index(b"?")
            parts[1] = uri[:q + 1] + b"x=0&" + uri[q + 1:]
            out[i][Raw].load = b" ".join(parts) + sep + rest
            break   # chi packet dau chua request line
```

Mirror vào `ai_agent/hidden_defender_env.py:apply_mech` (cùng logic — thêm
test byte-identity giữa 2 bản vào cuối `tests/test_query_param_prepend.py`
theo mẫu test T7 hiện có trong repo: cùng input, `mutate_client_only(...)`
vs `apply_mech(...)`, assert bytes bằng nhau trên mọi packet).

```bash
.venv/bin/python -m pytest tests/test_query_param_prepend.py tests/test_http_header_case.py -x -q
```
**Kỳ vọng:** pass hết. Commit:
`git commit -m "feat(P14.2): query_param_prepend -- break literal URI chains with a benign param"`

### T2.3 D5 + endpoint bar v2 (chỉ làm nếu citation đạt)

1. Nghiên cứu: RFC 3986 §2.1/§2.4 (percent-encoding, when to decode), tài
   liệu PHP `parse_str`/`$_GET` (parse query thành assoc array, key lạ bị
   bỏ qua nếu code chỉ đọc key cụ thể). Dùng `browser_exec` (web_extract
   không có backend). Mỗi quote verify bằng
   `~/.hermes/skills/research/grounded-citations/scripts/sources.py` →
   ledger. **Không đạt citation → DỪNG T2.3, mech vẫn đo bằng bar cũ và
   phân loại trung thực "endpoint-strict fail".**
2. Đạt → thêm vào `snort_validation/endpoint_model.py`:

```python
def _parse_http_q(raw: bytes) -> bytes | None:
    """Bar v2 (D5): lenh cua GET khong body = query da parse thanh
    key->value (percent-decoded, thu tu key theo lan xuat hien dau)."""
    head, sep, body = raw.partition(_HTTP_SEP)
    if not sep:
        return None
    parts = head.split(b"\r\n")[0].split(b" ")
    if len(parts) < 3 or not parts[0].isalpha():
        return None
    if body.rstrip(b"\x00"):
        return None              # bar v2 chi ap dung cho GET khong body
    uri = parts[1]
    if b"?" not in uri:
        return uri or None
    from urllib.parse import unquote_to_bytes, parse_qsl
    q = uri.split(b"?", 1)[1]
    pairs = parse_qsl(q.decode("latin-1"), keep_blank_values=True)
    return b"&".join(k.encode() + b"=" + v for k, v in pairs) or None
```
3. Nối vào scorer: trong `eval_pipeline.score_flow_real`, chỗ tính
   `valid_evasion_endpoint`, tính thêm `valid_evasion_endpoint_q` (cùng công
   thức nhưng parser `http_q` cho framing http) — **cell mới thêm key, không
   sửa key cũ** (tiền lệ backfill dualbar). Test RED trước:
   `tests/test_endpoint_q.py` — prepended-param URI parse ra cùng tập lệnh
   với URI gốc (so dict), URI đổi thứ tự param cũng bằng, URI đổi **giá trị**
   phải khác.

Commit: `git commit -m "feat(P14.3): endpoint bar v2 (parsed query, D5) -- citation-gated"`

### T2.4 Probe Snort thật (4 flow `2012533`, conf 52k)

Sửa `controls/p13_case_extended.py` thành bản tổng quát hơn HOẶC tạo
`controls/probe_param_prepend.py` (copy pattern): chấm
`noop,query_param_prepend,split8` trên đúng 4 flow
(3× neris-20110811 `list.php`, 1× fast-flux `94.63.150.63:80`) với
`--conf rulesets/p13/snort_et3000.conf`. 4 flow × 3 mech × ~70s ≈ **14 phút**,
chạy nền (`terminal background=true`), KHÔNG chạy trong subagent.

**Gate đóng băng trước:** `query_param_prepend` trên 4 flow:
`evaded=True` (SID 2012533 tắt) ∧ `valid_evasion_endpoint_q=True` (nếu D5
đạt) — còn bar byte kỳ vọng FAIL một cách trung thực (URI đổi bytes): ghi
vào report, không giấu. Flow `2018959` (sogou): KHÔNG probe — đã kết luận
không-slack phía client ở T0.3.

---

## Phase 3 — (TÙY CHỌN, chỉ khi Phase 1+2 chưa phủ hết mẫu số) `uri_value_percent`

Chỉ kích hoạt nếu T2.4 cho thấy `query_param_prepend` không tắt được
`2012533` trên ≥1 flow (vd Snort match pcre độc lập với content chain —
kiểm tra lại bằng chính kết quả probe, không suy diễn). Khi đó: percent-encode
100 ký tự hex của value `c=` (`%41%34...`), phá cả pcre lẫn chain; bắt buộc
D5 đạt citation. Chi phí +200B/flow — ghi vào bảng cost. TDD như Phase 2.
**Không làm trước khi có bằng chứng Phase 2 hụt** (YAGNI).

---

## Phase 4 — Đo lại toàn bộ oracle + cập nhật bảng

### T4.1 Sweep v9 (corpus cũ, mech đã sửa)

```bash
cd /root/.hermes/c2-evasion-rl
nohup .venv/bin/python controls/ownership_ceiling_sweep.py --split test \
  --ownership both --mechs "http_header_case" \
  --corpus snort_validation/reports/hidden_defender_corpus.pkl \
  --conf snort_validation/et_open_c2/snort_et_c2.conf \
  --out snort_validation/reports/ceiling_v9_casefix.json \
  > /tmp/v9_log.txt 2>&1 &
```
40 flow × 1 mech ≈ 15–20 phút (conf 21k). **Kỳ vọng:** 16/16 flow C2
`valid_evasion_endpoint=True` (14 cũ + 2 mới), 24 flow P2P ghi nhận riêng.

### T4.2 Chạy lại các oracle (không tốn Snort — dùng report)

```bash
.venv/bin/python controls/pareto_cost_oracle.py \
  --report snort_validation/reports/ceiling_v9_casefix.json --exclude split8,split16,split24,split_slow
.venv/bin/python controls/pareto_cost_oracle.py \
  --report snort_validation/reports/p13_v8_case_extended.json \
  --corpus snort_validation/reports/corpus_p13_extended.pkl
.venv/bin/python controls/composite_oracle.py --report <report_v9>   # theo CLI hien co
.venv/bin/python controls/sid_action_matrix.py --report <report_v9>
```
**Đọc kết quả theo D4:** coverage threat-model = số flow in-scope evaded /
mẫu số đóng băng T0.1 — không phải x/40 hay x/120 thô.

### T4.3 Cập nhật tài liệu

- `docs/headroom_root_cause.md`: thêm mục P14 (coverage không-split trước/sau).
- Plan P13 (`.hermes/plans/2026-10-13_120000-...md`): bảng "Chế độ
  KHÔNG-SPLIT" thêm cột cơ chế mới.
- `controls/verify_report_claims.py`: chạy, kỳ vọng **109/109** (+ claim mới
  nếu thêm); KHÔNG sửa verifier để pass.

---

## Tests / validation (tổng)

- Mỗi task code: RED (chạy pytest thấy fail đúng chỗ) → implement tối thiểu
  → GREEN → commit riêng. Test mới: `test_case_multipacket.py`,
  `test_query_param_prepend.py`, `test_endpoint_q.py`.
- Regression nhanh sau mỗi phase:
  `.venv/bin/python -m pytest tests/ -x -q --ignore=tests/archive`
  (kỳ vọng: toàn bộ pass; 3 fail cũ nằm ở `archive/tests/` — bỏ qua, pre-existing).
- Full regression cuối: `.venv/bin/python -m pytest tests/ -q` chạy nền.
- Byte-identity giữa `apply_mech` (env) và `mutate_client_only` (eval) cho
  mọi mech mới — bắt buộc, theo mẫu test T7 (55 cặp).

## Rủi ro / đánh đổi / câu hỏi mở

1. **T0.2 ra nhánh (c)** (baseline vốn không parse được): 2 flow đó chưa
   từng trong mẫu số endpoint → coverage không-split "thật" đã là 14/14;
   ghi nhận trung thực, Phase 1 đóng, không sửa gì.
2. **`query_param_prepend` không tắt `2012533`** (Snort có path match khác):
   đã dự phòng Phase 3; nếu cả hai hụt → negative result có kiểm soát, vẫn
   giá trị cho thesis (bảng "cơ chế × SID × reachable").
3. **D5 không đạt citation** → mech mới chỉ có bar byte (fail) + endpoint
   strict (fail) → không dùng được; dừng Phase 2.3, báo cáo.
4. **Chi phí Snort:** conf 52k ~70s/run, conf 21k ~15s/run. Tổng ngân sách
   plan: ~20 run probe (≈25 phút) + 1 sweep 40-run (≈20 phút). KHÔNG chạy
   sweep 15-mech đầy đủ (2460s+) khi chưa qua gate probe.
5. **Không đụng bar cũ, không đụng verifier, không dời D4 sau khi đo** —
   mọi con số báo cả thô lẫn threat-model.
6. Subagent (nếu dùng): cấm chạy Snort/full pytest; `workdir` = đường dẫn
   repo, không `cd &&`.

## Thứ tự thực thi đề xuất

T0.1 → T0.2 → T0.3 → T0.4 (freeze) → T1.1–1.3 → T2.1–2.2 → T2.3 →
T2.4 (probe nền) → [T3 nếu cần] → T4.1 (nền) → T4.2 → T4.3.

---

## KẾT QUẢ THỰC THI (2026-10-13, commit 14c591d → 7357aff)

| Phase | Việc | Kết quả |
|---|---|---|
| 0 | T0.1 denominator · T0.2 chẩn đoán · T0.3 slack từng SID | 3 kết luận đóng băng: chỉ 16 flow có slack trên corpus cũ, 4/37 trên corpus mở rộng |
| 0 | T0.4 quyết định D4-D7 | `docs/action_space_policy_p14.md` (file mới, không sửa file policy đã đóng băng) |
| 1 | D7 parser CL-aware | **Không sửa cơ chế** — nguyên nhân là parser nuốt POST pipelined. `http_header_case` 14 → **16/16** |
| 2 | D5 bar v2 + `query_param_prepend` | Citation đạt (RFC 3986 [6] + PHP parse_str [7]); **4/4 flow Virut né thật dưới Snort** |
| 3 | `uri_value_percent` | **BỎ (YAGNI)** — Phase 2 đã phủ 100% flow có slack |
| 4 | Đo lại oracle + docs | `docs/p14_results.md`; coverage không-split = 100% mọi flow có slack |

### Phát hiện ngoài dự kiến — bug đo thật (P14.3)

Probe độc lập trả `0 byte thay đổi` trên flow mà pipeline cho `+16`. Nguyên nhân:
scapy restore chuỗi layer **lazy**; process chưa import `scapy.all` trước khi
`pickle.load` thì `IP in pkt` / `Raw in pkt` trả **False** → cả flow rỗng →
bar False, cơ chế no-op im lặng. Sửa bằng `ensure_chain` ở
`c2_semantics.{reassembled_client_bytes, transport_payload, client_ip_of_packets,
server_ip_of}` + `eval_pipeline.mutate_client_only` + `apply_mech`;
`tests/test_scapy_lazy_unpickle.py` chạy subprocess trình mới để tái hiện.

> Pipeline chính **không** bị ảnh hưởng (nó import scapy trước), nhưng mọi
> probe độc lập sau này đều phải qua `ensure_chain`.

### Claim được phép viết (có bằng chứng)

1. Với mọi flow có **slack protocol phía client**, coverage không-split đạt
   **100%** (16/16 corpus cũ · 4/4 corpus mở rộng).
2. Phần chưa phủ là **đặc tính protocol/role**, không phải hạn chế action space:
   TLS ClientHello (`byte_test` độ dài), DNS sinkhole **response** của bên thứ ba.
3. Chi phí wire không-split: **+4…+8 B/flow, 0 fragment** (vs `split8` +10.744 B / 316 pkt).
