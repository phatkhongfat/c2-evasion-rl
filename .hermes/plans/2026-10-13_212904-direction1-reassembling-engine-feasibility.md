# Plan P16b — Feasibility Hướng 1 (defender engine có reassemble: Suricata / Snort 3)

**Ngày:** 2026-10-13 · **Branch:** `packet-level-rl` · **HEAD khi viết:** `a275c42`
**Bối cảnh:** plan P16 (`.hermes/plans/2026-10-13_211739-direction2-vs-direction3-feasibility.md`)
đã đóng gate cho Hướng 2 + Hướng 3. Plan này thêm **Hướng 1** vào cùng khung so sánh,
và trả lời câu "triển khai được không" bằng đo, không bằng nhận định.

**Loại plan:** feasibility có gate. **Deliverable = verdict Hướng 1 + bảng 3 hướng.**
"Không khả dụng" là kết quả đạt nếu bằng chứng nói vậy.

## Goal

Xác định bằng số đo thật: một engine **reassemble-then-detect** (Suricata 7 hoặc Snort 3)
có làm họ `split*` chết trên corpus đóng băng hay không, và nếu chết thì **geometry dị thể
của các rule còn lại** có tạo ra per-flow selection (headroom > 0) hay không — với ngân
sách Snort/Suricata bị chặn cứng.

## Current context / assumptions (đã recon read-only, 2026-10-13)

**Engine — trạng thái thật trên máy:**
```
which suricata      -> (không có)      # NOT INSTALLED
which snort         -> /usr/sbin/snort # 2.9.20-0+deb11u1ubuntu1 (apt candidate = same, KHÔNG có Snort 3)
apt-cache policy suricata -> Candidate: 1:7.0.3-1build3
df -h / -> 30G free (69% used) ; free -g -> 7G total, 1G free, 3G available
nproc = 4 ; load hiện ~2.0 (run train real-Snort pid 2409282 đang chạy)
```
→ **Suricata cài được bằng apt (7.0.3), Snort 3 KHÔNG cài được bằng apt** (phải build
từ nguồn: cần cmake + g++ + libdaq3 + pcre + luajit; trên máy 4 nhân/1GB RAM free là
rủi ro cao, và P16 đang cần CPU). **Chọn Suricata làm engine cho Hướng 1**, Snort 3 chỉ
là stretch (Task 4.4, có thể bỏ).

**Code cross-engine ĐÃ có nhưng CHƯA chạy được — đây là phát hiện quan trọng:**
- `controls/cross_engine_check.py` tồn tại (P4), gọi:
  `suricata -r <pcap> -S <rules> -l <workdir> -c snort_validation/suricata.yaml`
  và đếm alert bằng `p.stdout.count("[**]")`.
- Nhưng **cả hai file nó cần đều KHÔNG tồn tại**:
  `snort_validation/suricata.yaml` → missing; `snort_validation/et_open_c2/suricata.rules` → missing.
- Báo cáo cũ `snort_validation/reports/cross_engine_v2.json` (Oct 7, 946 bytes):
  5 cells, **`suricata evaded 0`, `warns 5`** → tức là **cả 5 lần gọi đều exception**
  (`n = -1`, dòng `except ... n = -1`). Vậy **chưa từng có một verdict Suricata thật nào**
  trong project. Mọi phát biểu "Suricata cũng vậy" trước đây là **chưa có bằng chứng**.
- Đếm alert bằng `stdout.count("[**]")` là **cách đo yếu**: Suricata ghi alert vào
  `fast.log`/`eve.json` trong `-l <dir>`, không chắc in `[**]` ra stdout ở chế độ mặc định.
  Phải sửa thành đọc `fast.log` (và đối chiếu `eve.json`) — đây là bẫy đo kiểu P14
  (scapy lazy-unpickle), phải test trước khi tin.

**Vì sao split thắng trên Snort 2.9 (đã chứng minh, `docs/headroom_root_cause.md:250-270`):**
`frag3` của Snort 2.9.20 chỉ **chọn fragment nào để đối chiếu rule** (`first`/`last`),
**không có chế độ reassemble-then-detect**; `snort -T` xác nhận `policy reassemble`,
`first_only`, `metis` đều `Bad policy name` (fatal=2). Conf đang dùng
(`snort_validation/et_open_c2/snort_et_c2.conf:45-49`):
```
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy first detect_anomalies
preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp yes
preprocessor stream5_tcp: policy first, use_static_footprint_sizes
```
→ Chữ ký trải trên nhiều IP fragment không bao giờ khớp, **độc lập cấu hình**.
Suricata **có** defrag + stream reassembly mặc định → **giả thuyết H1: split chết**.
Đây chính là giả thuyết phải đo, không phải kết luận.

**Hệ quả nếu H1 đúng (đây là phần "có triển khai được không"):**
Họ `split*` (5/17 action: `split8`, `split16`, `split24`, `split_slow`, `overlap8`) mất tác
dụng → 24 flow neris (UDP) và các flow chỉ né được bằng fragmentation **không còn đường
né** → coverage sụt. Trục còn lại là semantic-preserving rewrite (`http_header_case`
0 byte, `query_param_prepend` +4…+8 byte, `http_header_pad`) — **đúng loại cơ chế mà bar
D5/D7 + citation RFC 3986/PHP `parse_str` của P14 đã xây sẵn hạ tầng** (đúng như user nói).
Và `docs/rl_substantive_claim.md` đã ghi hướng này làm future work: *"dựng corpus có SID
families với match geometry KHÁC nhau — rules có `depth:`/offset neo đầu payload ... với
rules `fast_pattern` giữa stream ... Khi đó best_single < oracle theo cấu trúc."*

**Geometry dị thể có thật không — đã đọc rule text thật (bằng chứng cho gate G1b):**

| SID | classtype | trong mẫu D4? | clause geometry |
|---|---|---|---|
| 2012533 Virut | trojan-activity | ✅ (4 flow) | `GET ` **depth:4** ∧ `list.php?c=` **within:32** ∧ `&v=` **distance:0** ∧ `&t=` **distance:0** ∧ pcre |
| 2012627 FakeAV | trojan-activity | ✅ (16 flow) | 4 content **distance:0** chain, có `fast_pattern` giữa stream, **không** depth/offset |
| 2014635 Kazy TLS | trojan-activity | ❌ (no-slack, split-only) | `byte_test` — **Suricata hỗ trợ byte_test** → có thể ĐỔI kết luận P14.3! |
| 2018959 sogou | trojan-activity | ✅ (1 flow, to_client) | `within:2` |
| 2023753 RDP scan | attempted-recon | ❌ (D4 loại) | `depth:3` ∧ **offset:5 depth:6** ∧ `Cookie: mstshash=` fast_pattern |
| 2014169 / 2027863 .su DNS | bad-unknown | ❌ (D4 loại) | **offset:2 depth:1** ∧ `distance:1 within:7` |
| 2003255/61/67 | — | ❌ | **offset:8 depth:4** |

→ **Hai loại geometry đối lập cùng tồn tại**: (a) neo **đầu payload** bằng `depth:`/`offset:`
(2012533 clause 1, 2023753, 2014169, 2003255) — chỉ phá được bằng cách **dịch byte đầu**
(prepend/pad) hoặc fragment; (b) **chain giữa stream** bằng `distance:0`/`fast_pattern`
(2012627, 2012533 clause 2-4) — chỉ phá được bằng cách **chèn vào giữa** (param prepend,
case-flip). Một cơ chế cố định **không thể** tối ưu cho cả hai → đây là cơ sở *có thật*
cho per-flow selection, và nó là điều P13/P14 chưa đo được vì split che hết.

**Ràng buộc ngữ nghĩa (phải ghi trong gate, nếu không sẽ tự lừa mình):**
- Với (a) neo đầu payload: trên **HTTP**, chèn byte *trước* request line phá request →
  **fail D7/D5**. Vị trí chèn an toàn duy nhất là **trong header block** (sau request line)
  → **không dịch** byte 0..N của request line → **không phá được rule neo `depth:4`/`offset:5`
  trên request line**. Nghĩa là nhóm (a) **có thể bất khả xâm phạm** bởi rewrite an toàn,
  chỉ còn fragmentation (mà Suricata thì giết fragmentation). **Đây là rủi ro chính làm
  Hướng 1 fail G1b** và phải đo, không được giả định.
- Với **UDP/binary** (neris, DHT): mọi chèn đều phá record chain → nhóm (a) lẫn (b) đều
  không có slack an toàn. Vậy Hướng 1 nếu sống thì sống **trên HTTP flows**, và mẫu số
  phải là subset HTTP của D4 — ghi rõ, không âm thầm đổi mẫu số.

**Chi phí engine (phải đo ở Task 1.3, không được lấy số Snort áp dụng):**
Đã biết Snort conf 21k ≈ 20s/flow, conf 52k ≈ 70s/flow/mech. Suricata chưa có số nào.
Ngân sách cứng toàn plan: **≤ 90 phút** thời gian engine (cộng dồn), mọi task phải khai
báo số flow × số mech trước khi chạy.

**Nợ P15/P16 phải trả trước (không đổi so với plan P16 Phase 0):**
- Run train `--real-snort` seed 42 đang chạy (pid 2409282, epoch ~15/30, ~11,5 phút/epoch).
  **Mọi task engine phải chờ nó xong** (4 nhân, load đã 2.0).
- `99356c0` (replica direction fix) **fail calibration** (noop 40/40→36/40,
  `oracle_split8_test.json` 17/40→7/40) vì `snort_et_c2.conf:17-18` đặt
  `var HOME_NET any` / `var EXTERNAL_NET any` → header direction vô nghĩa trên conf này;
  và nó **no-op trên train path** (pickle nhúng `Rule` chưa có field `direction`,
  `git diff d01f4da a275c42` rỗng).
- Baseline client-only đúng là `oracle_split8_test.json` = **23/40** (http 16/16, neris 7/24);
  `ppo_masked_test.json` 40/40 là **both-ownership** (sinh ở `e6fb02d` 4/10, trước
  client-only `apply_mech` ở `40fffdf` 5/10).

## Architecture / proposed approach

Bốn pha, mỗi pha một gate viết trước. **Phase 1** dựng harness Suricata thật (cài engine,
viết `suricata.yaml`, convert ruleset, **sửa cách đếm alert** + test) và đo chi phí; gate G1a
= harness tái tạo được control âm tính. **Phase 2** đo giả thuyết cốt lõi "split chết" trên
chính 24+16 flow đã có số Snort 2.9 để đối chiếu; gate G1b = có ≥2 flow HTTP trong mẫu D4
mà **cơ chế tối ưu khác nhau**. **Phase 3** chỉ chạy nếu G1b pass: dựng bảng
`geometry × mechanism` để chứng minh headroom > 0 một cách có cấu trúc. **Phase 4** gộp
verdict Hướng 1 vào bảng 3 hướng và cập nhật `docs/p16_direction_verdict.md`.

---

## Phase 0 — Trả nợ (bắt buộc, ~25 phút, không engine)

Giữ nguyên T0.1–T0.5 của plan P16 (chờ train xong → revert *hành vi* direction fix →
viết `docs/baseline_ownership_provenance.md` → sửa A4 baseline trong plan P15 +
`docs/p15_train_results.md` → commit). **Không lặp lại ở đây.** Thêm một việc:

### T0.6 — Ghi trạng thái cross-engine cũ vào provenance (5 phút)

Append vào `docs/baseline_ownership_provenance.md` một mục `## Cross-engine (Suricata)`:
```
`controls/cross_engine_check.py` (P4) tham chiếu hai file KHÔNG tồn tại
(snort_validation/suricata.yaml, snort_validation/et_open_c2/suricata.rules) và
`snort_validation/reports/cross_engine_v2.json` có 5/5 cell = -1 (exception).
Kết luận: CHƯA từng có verdict Suricata thật nào trong project; không được trích
dẫn cross_engine_v2.json làm bằng chứng cross-engine.
```
Verify:
```bash
grep -c "cross_engine_v2" docs/baseline_ownership_provenance.md   # kỳ vọng >= 1
.venv/bin/python -c "import json;d=json.load(open('snort_validation/reports/cross_engine_v2.json'));print(sum(1 for c in d['cells'] if c['suricata_alerts']==-1), '/', len(d['cells']))"
# kỳ vọng: 5 / 5
```
Commit chung với T0.5.

---

## Phase 1 — Dựng harness Suricata + gate G1a

### T1.1 — Freeze gate G1 vào `docs/p16_direction_gates.md` (append section "G1")

Viết TRƯỚC khi chạy bất kỳ lệnh engine nào:

- **G1a (harness đúng):** Suricata chạy được trên ≥1 pcap thật và **tái tạo control âm
  tính**: `noop` trên **40/40** flow test cũ phải **alert 40/40** (đối chiếu
  `control_noop_real_snort.json` = 40/40 dưới Snort 2.9). Nếu < 40/40 → harness sai
  (rules convert thiếu, yaml sai, hoặc cách đếm alert sai) → **DỪNG, sửa harness, không
  diễn giải kết quả evasion**.
- **G1b (split chết + heterogeneity sống):** CẢ HAI:
  - (i) `split8` valid-evasion trên mẫu HTTP-D4 **giảm** so với số Snort 2.9 đã commit
    (http 16/16 trong `oracle_split8_test.json`). Nếu vẫn 16/16 → Suricata **không**
    reassemble theo cách ta cần → Hướng 1 fail, ghi trung thực.
  - (ii) Tồn tại **≥ 2 flow** trong mẫu HTTP-D4 mà **cơ chế tối ưu khác nhau**
    (cơ chế tối ưu = cơ chế rẻ nhất còn valid-evasion). Nếu một cơ chế duy nhất thắng
    mọi flow → best_single = oracle → headroom = 0 → Hướng 1 **không** tạo giá trị RL,
    dù split có chết.
- **G1c (chi phí):** thời gian engine cho toàn bộ Phase 2 ≤ **45 phút**. Vượt → giảm
    mẫu (ghi rõ đã giảm gì), **không** chạy qua đêm không giám sát.
- **Ràng buộc mẫu số:** Hướng 1 chỉ được claim trên **subset HTTP của mẫu D4**
  (16 flow FakeAV cũ + 4 flow Virut mở rộng = 20 flow), vì rewrite an toàn không tồn tại
  trên UDP/binary. Ghi rõ: đây **không** phải mở rộng mẫu số, mà là **thu hẹp** — và
  mọi bảng phải in cả `x/20 (HTTP-D4)` lẫn `x/40 (full test)` để không ai đọc nhầm.
- **Anti-gaming:** không được chọn ruleset con để làm split chết; phải dùng đúng
  ruleset đã commit (21k `et_open_c2.rules`), convert **không lọc** nội dung rule.

### T1.2 — Cài Suricata + viết config (10 phút)

```bash
apt-get install -y suricata 2>&1 | tail -3     # kỳ vọng: Setting up suricata (1:7.0.3-1build3)
suricata -V                                     # kỳ vọng: Suricata version 7.0.3
suricata --build-info 2>/dev/null | grep -i "defrag\|Magic" | head -3
```
Tạo `snort_validation/suricata.yaml` — **KHÔNG viết tay từ đầu**: copy
`/etc/suricata/suricata.yaml` (file mặc định Debian) rồi sửa **tối thiểu** 4 chỗ:
```bash
cp /etc/suricata/suricata.yaml snort_validation/suricata.yaml
```
1. `default-rule-path` → đường dẫn tuyệt đối `snort_validation/et_open_c2`
2. `HOME_NET: "[any]"` và `EXTERNAL_NET: "[any]"` — **giữ `any` có chủ đích**, để khớp
   đúng hành vi `snort_et_c2.conf:17-18` (`var HOME_NET any`) mà P15 vừa chứng minh là
   khiến Snort match cả hai chiều. Ghi comment trong yaml: *"deliberately any, mirrors
   snort_et_c2.conf so the two engines see the same traffic scope"*.
3. `outputs: - fast:` → `enabled: yes`, `filename: fast.log`; `- eve-log:` → `enabled: yes`,
   `filename: eve.json`, types gồm `alert`.
4. Tắt thứ không cần để giảm nhiễu + tăng tốc: `- unified2:` enabled no; `pcap-log` no;
   `engine-analysis` giữ mặc định.
Verify (không cần rules):
```bash
suricata -T -c snort_validation/suricata.yaml -S snort_validation/et_open_c2/et_open_c2.rules \
  --set classification-file=/etc/suricata/classification.config 2>&1 | tail -5
# kỳ vọng: "Configuration provided was successfully loaded" (hoặc 0 error);
# NẾU báo lỗi cú pháp rule -> xem T1.3, KHÔNG sửa tay từng rule.
```

### T1.3 — Convert ruleset Snort→Suricata + kiểm số rule nạp được (10 phút)

Suricata 7 đọc **hầu hết** rule Snort 2.9, nhưng một số keyword gây error
(`tag:` kiểu cũ, `dynamic`/`established` kết hợp lạ, `reference:` không sao). Nguyên tắc:
**không lọc nội dung, chỉ loại dòng Suricata từ chối nạp, và ĐẾM + GHI RA số đã loại.**

```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python controls/convert_rules_for_suricata.py \
  --in snort_validation/et_open_c2/et_open_c2.rules \
  --out snort_validation/et_open_c2/suricata.rules \
  --reject-log snort_validation/et_open_c2/suricata_rejected.txt
```
Script mới `controls/convert_rules_for_suricata.py` (~60 dòng) làm đúng 3 việc:
1. Copy nguyên văn mọi dòng `alert ...`;
2. Với dòng chứa keyword Suricata 7 không hỗ trợ (duy trì một hằng số
   `UNSUPPORTED_SURICATA = ("snort_")` — **bắt đầu rỗng**, chỉ thêm khi `suricata -T`
   thật sự báo lỗi keyword đó, và mỗi lần thêm phải ghi lỗi nguyên văn vào reject-log),
   ghi vào reject-log;
3. In: `total=<N> kept=<K> rejected=<R>` + `rejected_sids_sample=[...]`.

Kỳ vọng: `total=21374 kept=21374 rejected=0` (Suricata 7 tương thích ET Open). Nếu
`rejected > 0`: **dừng lại**, đọc reject-log, và ghi số vào verdict — một ruleset bị cắt
thì G1b(i) không còn ý nghĩa (split "chết" có thể do thiếu rule).

Verify nạp được:
```bash
suricata -T -c snort_validation/suricata.yaml -S snort_validation/et_open_c2/suricata.rules 2>&1 | grep -iE "error|warn|loaded|rules" | tail -8
# kỳ vọng: không có dòng "ERROR"; số rule loaded ~21374
```

### T1.4 — TDD: sửa cách đếm alert (đây là bẫy đo, phải test trước)

`cross_engine_check.py` đếm `p.stdout.count("[**]")` — chưa từng được chứng minh. Viết
test **trước**, dùng pcap thật đã biết có alert:

`tests/test_suricata_alert_count.py`:
```python
"""P16b: Suricata alert counting must be proven on a known-alerting pcap.

cross_engine_v2.json has 5/5 cells = -1 (exception), so no Suricata verdict has
ever existed in this project.  This test pins the counting method BEFORE any
evasion measurement uses it -- same discipline as the P14 scapy lazy-unpickle bug.
"""
import json, shutil, subprocess, sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "snort_validation"), str(ROOT / "ai_agent")]

KNOWN_ALERT_PCAP = ROOT / ("data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-9/"
                           "2013-08-20_captureWin5.pcap")   # 295.199 B, đã dùng cho snort -T
YAML = ROOT / "snort_validation/suricata.yaml"
RULES = ROOT / "snort_validation/et_open_c2/suricata.rules"

pytestmark = pytest.mark.skipif(
    shutil.which("suricata") is None or not RULES.exists(),
    reason="suricata binary or converted ruleset not present")


def test_fast_log_counts_alerts_on_a_known_alerting_pcap(tmp_path):
    from suricata_runner import count_alerts          # module mới, T1.5
    n = count_alerts(KNOWN_ALERT_PCAP, RULES, YAML, tmp_path)
    assert n > 0, "known-alerting capture scored 0 -- counting method is broken"
    # đối chiếu hai nguồn độc lập: fast.log và eve.json
    eve = [json.loads(l) for l in (tmp_path / "eve.json").read_text().splitlines() if l.strip()]
    n_eve = sum(1 for e in eve if e.get("event_type") == "alert")
    assert n_eve > 0
    assert abs(n - n_eve) <= max(1, n_eve // 10), f"fast.log {n} vs eve {n_eve} disagree"


def test_empty_pcap_scores_zero(tmp_path):
    from suricata_runner import count_alerts
    from scapy.all import Ether, IP, UDP, wrpcap
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [Ether() / IP(src="203.0.113.9", dst="203.0.113.10") / UDP(sport=1, dport=2)])
    assert count_alerts(p, RULES, YAML, tmp_path) == 0
```

Chạy RED:
```bash
.venv/bin/python -m pytest tests/test_suricata_alert_count.py -q
# kỳ vọng FAIL: ModuleNotFoundError: No module named 'suricata_runner'
```

### T1.5 — GREEN: `snort_validation/suricata_runner.py`

```python
"""Run Suricata on one pcap and count alerts from fast.log + eve.json.

Replaces the unverified `stdout.count("[**]")` in controls/cross_engine_check.py,
which produced 5/5 exceptions in cross_engine_v2.json.  Counting from the log
FILES (not stdout) is what Suricata actually documents; eve.json is the
structured cross-check.
"""
from __future__ import annotations
import json, subprocess
from pathlib import Path
from typing import Sequence

TIMEOUT_S = 300


def run_suricata(pcap: Path, rules: Path, yaml: Path, logdir: Path) -> None:
    logdir.mkdir(parents=True, exist_ok=True)
    for stale in ("fast.log", "eve.json"):
        (logdir / stale).unlink(missing_ok=True)
    cmd = ["suricata", "-c", str(yaml), "-S", str(rules),
           "-r", str(pcap), "-l", str(logdir), "-k", "none", "--init-errors-non-fatal"]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=TIMEOUT_S)
    if p.returncode != 0:
        raise RuntimeError(f"suricata rc={p.returncode}: {p.stdout[-800:]}")


def count_alerts(pcap: Path, rules: Path, yaml: Path, logdir: Path) -> int:
    run_suricata(pcap, rules, yaml, logdir)
    fast = logdir / "fast.log"
    if not fast.exists():
        return 0
    return sum(1 for line in fast.read_text(errors="ignore").splitlines()
               if "[**]" in line)


def alert_sids(pcap: Path, rules: Path, yaml: Path, logdir: Path) -> Sequence[int]:
    """Signature IDs from eve.json -- needed to attribute WHICH rule fired."""
    run_suricata(pcap, rules, yaml, logdir)
    eve = logdir / "eve.json"
    if not eve.exists():
        return []
    out = []
    for line in eve.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("event_type") == "alert":
            out.append(int(rec["alert"]["signature_id"]))
    return out
```
Chạy GREEN:
```bash
.venv/bin/python -m pytest tests/test_suricata_alert_count.py -q
# kỳ vọng: 2 passed  (nếu skip -> suricata/rules chưa có, quay lại T1.2/T1.3)
```
Commit: `feat(P16b.1): Suricata harness -- yaml, ruleset conversion, proven alert counting`

### T1.6 — Đo chi phí engine + gate G1a (control âm tính)

Tạo `controls/suricata_probe.py`:
- nhận `--flows <N>` (mặc định 5), `--mechs noop`, `--corpus`, `--split test`
- với mỗi (flow, mech): `mutate_client_only` (hoặc noop) → `translate_source` (như
  `cross_engine_check.py` đang làm, để tránh trùng 5-tuple) → `wrpcap` → `count_alerts`
- in `wall_s` tổng + trung bình/flow, ghi `snort_validation/reports/suricata_probe_p16.json`

```bash
# CHỈ chạy khi T0.1 xác nhận train real-Snort đã xong
ps -eo args | grep -c "[s]nort"        # kỳ vọng 0
time .venv/bin/python controls/suricata_probe.py --flows 5 --mechs noop
```
Kỳ vọng: `noop alert 5/5`; `mean_s_per_flow` được in ra. **Nhân số đó với
(20 flow × 4 mech × 2 engine-state) để kiểm G1c ≤ 45 phút trước khi vào Phase 2.**
Nếu vượt: giảm mẫu xuống 12 flow HTTP-D4 và ghi rõ vào verdict.

Gate **G1a**: chạy đủ 40 flow noop:
```bash
.venv/bin/python controls/suricata_probe.py --flows 40 --mechs noop \
  --out snort_validation/reports/suricata_control_noop_p16.json
# kỳ vọng: alerted 40/40 (bằng control_noop_real_snort.json). NẾU < 40 -> DỪNG, harness sai.
```
Commit: `feat(P16b.2): Suricata control -- noop must alert 40/40 (G1a)`

---

## Phase 2 — Đo giả thuyết "split chết" + heterogeneity (gate G1b)

### T2.1 — Bảng engine-đối-chứng trên mẫu HTTP-D4

Tạo `controls/engine_matrix.py`: chạy **cùng một tập (flow, mech)** qua Suricata, với
`mechs = noop,split8,split24,split_slow,http_header_case,query_param_prepend,http_header_pad`
(7 mech — bỏ `overlap8`/`corrupt8` vì đã biết phá ngữ nghĩa). Với mỗi cell ghi:
`suricata_alerts`, `evaded`, `sids` (từ `alert_sids`), và **bar ngữ nghĩa tính in-process**
(`endpoint_commands_preserved` D7, `endpoint_query_preserved` D5, `bytes_equal_semantics`)
→ `valid_evasion_d5` = `evaded and (d7 or d5)` theo đúng D8 đã freeze.

Mẫu: 20 flow HTTP-D4 (16 FakeAV cũ lấy từ `hidden_defender_corpus.pkl` split=test
framing=http; 4 Virut lấy từ `corpus_p13_extended.pkl` theo flow_id trong
`p13_v9_query_prepend.json`). **Đóng băng danh sách flow_id vào
`docs/p16b_denominator_http.md` TRƯỚC khi chạy** (kế thừa kỷ luật `docs/p14_denominator.md`).

```bash
.venv/bin/python controls/engine_matrix.py --engine suricata \
  --out snort_validation/reports/engine_matrix_suricata_p16.json
# ngân sách: 20 flow x 7 mech = 140 run; nhân mean_s_per_flow từ T1.6 -> PHẢI <= 45 phut
```
Đối chứng Snort 2.9: **không chạy lại**. Lấy từ report đã commit:
`oracle_split8_test.json` (split8 client-only: http 16/16),
`ceiling_v6_case_fullrules_qbar.json` (http_header_case),
`p13_v9_query_prepend.json` (query_param_prepend 4/4), `p14_v10_qpp_old_corpus.json` (0/16).
Chỗ nào thiếu mech (ví dụ `http_header_pad` trên 4 Virut) → ghi `not_measured`, **không suy diễn**.

### T2.2 — Chấm gate G1b + verdict Hướng 1

Append vào `docs/p16_direction_gates.md` section **"Verdict G1"**, ba bảng bắt buộc:

1. **Bảng split:** `split8` valid-evasion, Snort 2.9 vs Suricata, trên 16 flow HTTP cũ
   và 4 flow Virut. G1b(i) PASS nếu Suricata **thấp hơn**.
2. **Bảng cơ chế tối ưu per-flow:** mỗi flow một dòng → mech rẻ nhất còn valid
   (theo `ACTION_COSTS` đã freeze ở D10). G1b(ii) PASS nếu **≥ 2 flow có mech tối ưu
   khác nhau**.
3. **Bảng headroom:** `best_single` (cơ chế cố định tốt nhất trên toàn mẫu) vs
   `per_flow_oracle` (tổng cost của mech tối ưu từng flow), tính bằng `controls/pareto_cost_oracle.py`
   với `--bar` D5 — **dùng lại tool P14.5, không viết oracle mới** (DRY). Ghi cả
   `--no-frag` regime.

```bash
.venv/bin/python controls/verify_report_claims.py    # kỳ vọng pass (>= 109 checks)
git add docs/ controls/ snort_validation/reports/ tests/ && git commit -F /tmp/p16b_msg_2.txt
```

---

## Phase 3 — CHỈ KHI G1b PASS: chứng minh headroom có cấu trúc

### T3.1 — Map `geometry × mechanism` (không engine)

Mở rộng `controls/rule_geometry.py` (đã có sẵn logic đọc `content:` length L) thêm hàm
`anchor_class(rule) -> "head_anchored" | "mid_chain" | "unanchored"` dựa trên
`depth:`/`offset:` (head) vs `distance:0`/`within:` + `fast_pattern` (mid-chain).
Verify bằng 2 SID đã biết trước kết quả (test):
```bash
.venv/bin/python -m pytest tests/test_anchor_class.py -q
# kỳ vọng: 2012533 -> head_anchored (depth:4 clause 1) ; 2012627 -> mid_chain (4x distance:0, fast_pattern)
```

### T3.2 — Bảng "vì sao mech này thắng flow kia"

Với mỗi flow trong mẫu HTTP-D4: SID đã bị hạ (`alert_sids` trước/sau), `anchor_class`
của SID đó, mech tối ưu. Kỳ vọng bảng cho thấy **head_anchored ↔ pad/prepend** và
**mid_chain ↔ case/param** — tức là headroom có **nguyên nhân cấu trúc**, không phải
nhiễu. Nếu bảng không tách được hai nhóm → ghi "heterogeneity không giải thích được bằng
geometry" và **hạ claim** xuống mức thực nghiệm.

### T3.3 — Bất biến bắt buộc (chống tự lừa)

- Bar **byte** vẫn FAIL cho `http_header_case`/`query_param_prepend` → báo nguyên trạng.
- `2014635` Kazy TLS: Suricata **có** `byte_test` → phải đo lại xem kết luận "no client-side
  slack" của P14.3 còn đứng không. Nếu Suricata bắt được mà Snort 2.9 không (hoặc ngược
  lại) → đó là **phát hiện engine-dependence**, ghi vào verdict, KHÔNG sửa kết luận P14 cũ.
- Không xóa `split*` khỏi action space kể cả khi Suricata giết chúng (anti-gaming clause
  trong `docs/action_space_policy.md`); claim phải theo **regime engine**, giống hệt cách
  P14.6 claim theo regime fragmentation.

---

## Phase 4 — Verdict 3 hướng + quyết định

### T4.1 — Cập nhật `docs/p16_direction_verdict.md`

Thêm cột **Hướng 1** vào bảng 7 trục của P16 Phase 4, và một bảng tổng kết:

| trục | Hướng 1 (engine reassemble) | Hướng 2 (adaptive) | Hướng 3 (parameterized) |
|---|---|---|---|
| Gate | G1a/G1b/G1c | G2a–G2d | G3a–G3c |
| Cài mới | apt install + yaml + convert + runner (~2 giờ) | benign pool + patch operator + validate (~3 giờ) | wrapper tham số + có thể bar mới |
| Tái dùng | **bar D5/D7, corpus, verifier, pareto oracle** | bar + corpus | bar + corpus + primitive `split_fragments(payload, split_at)` đã parameterized |
| Rủi ro chính | rewrite an toàn **không dịch được byte đầu** → nhóm head-anchored bất khả xâm phạm → headroom vẫn 0 | defender là artifact ta viết → cần 3 điều kiện G2b | AND-chain ⇒ mọi tham số **equivalent** (rule anchored thì bị D4 loại) |
| Surrogate dùng được? | **Không** (mọi cell là engine thật) | Không (pcre) | Một phần |
| Chi phí engine | 20 flow × 7 mech ≈ đo ở T1.6 | ~12 phút/vòng (đã đo P16 Phase 3) | ~8 phút lưới nhỏ |

### T4.2 — Stretch (tùy chọn, chỉ khi còn ngân sách): Snort 3

Build từ nguồn là rủi ro (cmake, libdaq3, luajit, 1GB RAM free). Nếu làm: `Task 4.4`
ghi rõ `apt-get build-dep`, build trong `tmux`, và **dừng ngay** nếu build > 40 phút.
Giá trị: xác nhận kết luận không phải artifact của riêng Suricata. Nếu bỏ: ghi
"Snort 3 not attempted: not in apt, build cost exceeds budget" — trung thực, không im lặng.

### T4.3 — Commit + memory/skill

```bash
git add docs/p16_direction_verdict.md docs/p16_direction_gates.md && git commit -F /tmp/p16b_msg_4.txt
```
Nếu phát hiện bẫy đo mới (ví dụ đếm alert từ stdout sai): `skill_manage patch`
`c2-evasion-rl/references/scoring-pitfalls.md` mục 5.

---

## Tests / validation

- TDD bắt buộc cho: `suricata_runner.count_alerts` (T1.4/T1.5 — **đây là gate chống bẫy
  đo, không được bỏ qua**), `convert_rules_for_suricata` (test: rule có `pcre` + `byte_test`
  phải được giữ nguyên văn; test: reject-log ghi đúng SID khi một rule bị loại),
  `anchor_class` (T3.1, với 2 SID đã biết trước đáp án).
- `controls/engine_matrix.py` là script đo → validation bằng **control âm tính** (noop
  phải alert 40/40) và bằng **đối chiếu chéo** với report Snort 2.9 đã commit, không
  phải unit test phủ nhánh.
- Sau mỗi commit code: chạy **chỉ** các file named
  ```bash
  .venv/bin/python -m pytest tests/test_suricata_alert_count.py tests/test_anchor_class.py \
    tests/test_replica_direction.py tests/test_post_p14_actions.py \
    tests/test_reward_semantic_gate.py tests/test_semantics_bar_agreement.py -q
  ```
  Kỳ vọng: all passed (test suricata được phép **skip** nếu binary/rules vắng).
- Full suite chạy nền giữa các phase (`background=true` + `process_manage wait`); baseline
  hiện tại là **344 passed, 1 skipped** sau `e651b65`.
- `controls/verify_report_claims.py` ≥ 109 sau Phase 2 và Phase 4.

## Risks, tradeoffs, open questions

1. **Rủi ro giết chết Hướng 1 (đã nêu ở phần context):** trên HTTP, vị trí chèn **an toàn
   về ngữ nghĩa** duy nhất là header block (sau request line), nên nó **không dịch** các
   byte mà rule head-anchored (`depth:4`, `offset:5`) neo vào. Nếu đúng vậy, khi
   fragmentation bị Suricata vô hiệu, nhóm head-anchored trở thành **bất khả xâm phạm bởi
   rewrite an toàn** → coverage giảm và headroom vẫn 0. Phase 2 đo đúng điều này; nếu nó
   xảy ra thì verdict là "Hướng 1 làm bài toán **khó hơn**, không làm RL **cần hơn**" —
   vẫn là kết quả có giá trị (và là khuyến nghị phòng thủ: bật defrag).
2. **Engine-dependence của toàn bộ project:** nếu Suricata và Snort 2.9 bất đồng về cùng
   một (flow, mech), thì **mọi con số đã công bố đều là "dưới Snort 2.9 + conf này"**.
   Đây là rủi ro cho thesis nhưng cũng là một **đóng góp**: đo mức engine-dependence của
   packet-level evasion. Bắt buộc ghi scope vào mọi bảng.
3. **Cài package hệ thống** (`apt-get install suricata`) là mutating action ngoài repo —
   phải hỏi user trước khi chạy (plan mode không cho phép; khi thực thi vẫn nên xác nhận).
4. **CPU/RAM:** 1GB free + run train real-Snort đang chạy. T0.1 là gate cứng. Không chạy
   Suricata song song Snort.
5. **Chi phí convert 21.374 rule:** `suricata -T` trên 21k rule có thể chậm (vài phút) và
   tốn RAM; nếu OOM → dùng `build_c2_only_ruleset.py` (đã có) để lấy subset C2 **nhưng
   phải ghi rõ subset** và không được claim trên toàn ruleset.
6. **Không có số Snort 2.9 cho mọi mech trên mọi flow** (ví dụ `http_header_pad` trên 4
   Virut) → bảng đối chiếu sẽ có ô `not_measured`. Chấp nhận; **không** chạy thêm Snort
   để lấp ô nếu ngân sách G1c đã cạn.
7. **Open question cho user (hỏi ở Phase 4):** nếu cả Hướng 1 và Hướng 2 đều pass gate,
   chọn cái nào cho thesis? Hướng 1 cho **positive result có cấu trúc** (geometry → per-flow
   selection) nhưng phụ thuộc engine; Hướng 2 cho **metric mới** (survival time) và tránh
   hẳn tranh cãi "best_single tối ưu" nhưng defender là artifact tự viết.
8. **Open question kỹ thuật:** có nên đưa **Suricata làm defender thứ hai trong vòng
   adaptive** (Hướng 1 × Hướng 2) không? Engine rotation = một dạng defender adaptation
   rất tự nhiên và **không phải ta tự viết patch** (tránh được rủi ro #1 của Hướng 2).
   Chỉ xét sau khi cả hai gate pass.
