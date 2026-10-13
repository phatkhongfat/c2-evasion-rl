# P13 — Mở rộng không gian hành động: thêm ruleset + thêm traffic, đo bằng SID-action matrix

## Trạng thái 2026-10-13 (đã thực thi, cập nhật liên tục)

| Task | Trạng thái | Kết quả |
|---|---|---|
| T0.1 `sid_diversity.py` | ✅ xong, 20 test | S1 = **0** |
| T0.2 `sid_action_matrix.py` | ✅ xong | S2 = **0** (mọi SID chung 1 tập cơ chế) |
| T0.3 sweep 15 cơ chế | ⛔ **bỏ** — dữ liệu đã có sẵn | dùng `ceiling_v4_both_test_dualbar` |
| T0.4 `composite_oracle.py` | ✅ xong | composite headroom = **0** dưới cả 2 bar |
| T1.1 tải ET Open 3.0.0 | ✅ 52.454 rule, `snort -T` pass | superset của ruleset cũ |
| T1.2 freeze danh sách | ✅ `rulesets/p13/MANIFEST.md`, `88a6d43` | trước mọi phép đo headroom |
| T2.1 cứu `/tmp/cov` | ✅ 5 capture có alert thật → `snort_validation/alert_cov/` | không còn phụ thuộc `/tmp` |
| T2.2 mở rộng traffic 2→15 capture | ✅ xong, `222f89a` | **8 capture có alert**, 40 SID phân biệt |
| T2.3 corpus mở rộng | ✅ 216 flow / 8 capture | `corpus_p13_extended.pkl` |
| T3.1 đo S1 theo **priority của rule** | ✅ xong, `76a7088` | S1 **thật = 3 flow**, không phải 380 |
| T3.2 S2 / composite trên ruleset mới | ✅ xong, `00e8b3d` + `cf5a1a1` | **0/120 flow** có 2 rule malware độc lập (13 flow SSH-scan noise, 1 flow DNS TLD) |
| T4.1 case-mech trên corpus mở rộng | ✅ xong, `262009f` | `http_header_case` **0/5** — không transfer (flow mới bị rule URL-content bắt, không phải header-case) |
| T4.2 **cost-axis Pareto oracle** | ✅ xong, `3dc3f28` + `81108e2` | **HEADROOM DƯƠNG ĐẦU TIÊN** — xem mục dưới |

**Kết luận Phase 0 (chưa đổi ruleset, chưa đổi traffic):** `headroom = 0` dưới cả
hai bar, và **giờ đã biết vì sao** — không chỉ vì `best_single` = 100%, mà vì
**composite headroom cũng bằng 0**: không có flow nào mà *tập hợp* cơ chế né được
trong khi *không cơ chế đơn lẻ nào* né được. Đây là phép đo mà `rl_headroom.py`
cũ không thể làm (nó chỉ thử từng cơ chế một).

---

## Goal

Xác định bằng đo liệu có tồn tại một flow mà **hai cơ chế khác nhau, cùng hợp lệ
và cùng né được, đều bị dập bởi SID khác nhau** — và nếu có, mở `headroom > 0`
mà không tinh chỉnh ngưỡng theo kết quả. Nếu không, chứng minh `headroom = 0` là
đặc tính của **mọi** ruleset × traffic khả dĩ, không chỉ của bộ hiện tại.

---

## Current context — đo đạc đã có, và nó **mâu thuẫn với tiền đề của yêu cầu**

Yêu cầu: "tải thêm ruleset để nâng độ khó evade, tạo RL improve space". Đo đạc
hôm nay cho thấy nút thắt **không nằm ở thiếu rule**:

| Quan sát | Nguồn | Ý nghĩa |
|---|---|---|
| Ruleset hiện tại đã nạp **21374 rule** | `grep -cE '^\s*(alert\|drop\|pass\|reject\|log)\s' snort_validation/et_open_c2/et_open_c2.rules` | Không phải thiếu lượng rule |
| Mỗi flow C2 trong threat model khớp **đúng 1 SID** | `ceiling_v6_case_fullrules.json`, 40 flow | Không có gì để "chọn" |
| 23/40 flow có ≥2 SID, nhưng **tất cả** là `(2008581, 2008583)` / `(2008581, 2008585)` — BitTorrent DHT, đã loại khỏi threat model ở P11 | cùng nguồn | Đa SID hiện có **không nằm trong threat model** |
| **0/40 flow** nào có `2012627` (C2 thật) cùng SID khác | cùng nguồn | Per-flow selection bất khả thi trên ruleset hiện tại |

**Suy ra:** `headroom = 0` hiện tại là hệ quả của *"mỗi flow chỉ có một rule
áp dụng"*, không phải của *"ruleset quá dễ"*. Thêm rule chỉ có ích nếu thêm rule
đó **cùng khớp** một flow đã có rule khác.

**Nhưng traffic thì thiếu thật** — và đây mới là trục khai thác cao nhất:

| Nguồn | Trạng thái |
|---|---|
| Capture trên đĩa | **21 file** trong `data/stratosphere/` |
| Capture đã đưa vào corpus lớn | **2** (`botnet-capture-20110811-neris`, `botnet-capture-20110819-bot`) |
| Capture chưa dùng | **13**, gồm 7 họ malware: rbot, fast-flux, rbot-dos, donbot, qvod, sogou, neris-20110810, + 8 capture Windows |
| Alert Snort `-A fast` đã harvest | **còn nguyên** trong `/tmp/cov/<capture>/alert` — **không cần chạy lại Snort để tìm SID** |

SID đang bắn trên traffic chưa dùng (đọc từ `/tmp/cov`, không tốn Snort):

| Capture | flows | SID |
|---|---:|---|
| `botnet-capture-20110812-rbot` | 3 | **2019471 + 2019486** |
| `botnet-capture-20110815-rbot-dos` | 2 | **2019471 + 2019486** |
| `botnet-capture-20110810-neris` | 52 | 2012533 + 2014169 (tách bạch) |
| `botnet-capture-20110815-fast-flux` | 4 | 2012533 + 2014635 (tách bạch) |
| `capture-win13` | 911 | 2016413 |
| 8 capture còn lại | 0 | *(không SID nào bận dưới ruleset C2-only)* |

---

## Kết quả Phase 1–3 — S1 pass trên giấy, fail trong threat model

### Đo trên ruleset 52.454 rule + 15 capture (harvest `222f89a`)

| capture | alerts | SID | SID trong threat model |
|---|---:|---:|---:|
| 20110812-rbot | 38.150 | 19 | 19 |
| 20110810-neris | 527 | 13 | 13 |
| 20110811-neris | 519 | 13 | 13 (có `2012627`) |
| 20110816-qvod | 632 | 11 | 11 |
| 20110816-donbot | 124 | 6 | 6 |
| 20110815-fast-flux | 11 | 4 | 4 |
| 20110816-sogou | 5 | 2 | 2 |
| capture-win13 | 939 | 1 | 1 |
| 7 capture còn lại | 0 | 0 | 0 |

Đây là bước nhảy thật so với ruleset C2 cũ: trước đó **mọi** capture có alert
đều chỉ có đúng **một** SID trong threat model. Giờ 7/8 capture có ≥2 SID.

### Nhưng S1 đó là scan noise

Đo S1 theo 5-tuple trên file alert:

| ngưỡng priority | 5-tuple có alert | ≥2 SID | SID set phổ biến nhất |
|---:|---:|---:|---|
| ≤ 3 | 24.161 | **380** | x347 `2001219`+`2003068` (SSH scan) |
| ≤ 2 | 22.127 | **367** | x347 `2001219`+`2003068` (SSH scan) |
| **≤ 1** | **928** | **3** | x3 `2019471`+`2019486` (IRC bot) |

Rule phổ biến nhất theo số alert là `2003068` **ET SCAN Potential SSH Scan
OUTBOUND** với 21.039 hit. Rule scan cùng bắt trên 5-tuple với traffic C2
thật, nên đếm chúng là SID phân biệt làm thổi phồng gate.

**Priority là metadata của rule, không liên quan gì tới việc flow có bị né hay
không** → phân tầng theo priority không phải hạ bar theo kết quả. Priority 1
đúng là bậc "high likelihood of a security problem" của ET, và nó chứa đúng
các rule malware (`2012627` FakeAV C2 check-in, `2019471`/`2019486` IRC bot).

### Kết luận

Với **52.454 rule** (2,5×) và **8 capture** (4×), chỉ **3 flow** thật có ≥2 SID
— và cả 3 đều là **cùng một cặp** `(2019471, 2019486)` trên IRC port 6667, đúng
dạng thoái lui đã ghi ở phần trên. Không có tổ hợp SID nào *độc lập* mà các
cơ chế hiện có bắt buộc phải xử lý bằng hai nhánh khác nhau.

### Sweep baseline `noop` trên corpus mở rộng (8.759s, commit `00e8b3d`)

120 test flow, conf 52k. Hai phát hiện, **cả hai đều phủ định**:

**1. `ceiling_valid_evasion = 5` là artifact, không phải kết quả.** Đúng bằng số
flow không có alert nào ở baseline (5/120). Vì `evaded := (n_alerts == 0)` trong
`eval_pipeline.py:484` không phân biệt *"né được alert"* với *"vốn không có alert
để né"*, flow không bị rule nào bắt được tính là evasion hợp lệ. Mọi con số
"evaded" phải đọc kèm `baseline_alert=True`.

**2. Không có flow nào có hai rule malware độc lập.**

| loại | số flow | SID | priority |
|---|---:|---|---|
| SSH scan (in+out) | 13 | `2001219` + `2003068` | 2 |
| DNS TLD (.su + .biz) | 1 | `2014169` + `2027863` | 2 |
| **2 rule malware (pri 1)** | **0** | — | — |

Cặp SSH scan là threshold detector **không có `content` match nào**; cặp DNS chỉ
là hai rule cùng đọc query name ở hai TLD. 7 SID priority 1 trong harvest
(`2012533` Virut, `2012627` FakeAV, `2014635` Kazy, `2016413` sinkhole,
`2018959` PE download, `2019471`/`2019486` IRC) **không cặp đôi** trên bất kỳ
flow nào.

→ **Mở rộng ruleset 2,5× và traffic 4× vẫn không tạo ra tổ hợp SID độc lập.**
Cấu trúc "mỗi flow một rule" không phải hạn chế của corpus cũ.

### Phát hiện DƯƠNG đầu tiên: headroom trên trục CHI PHÍ (commit `81108e2`)

Evasion headroom = 0, nhưng **wire cost là trục thứ hai hợp pháp mà attacker
quan tâm** (băng thông, số packet — cơ chế fragmentation đắt hơn đổi case
header vốn zero-cost). `controls/pareto_cost_oracle.py` đo: *per-flow policy
chọn cơ chế VALID rẻ nhất* vs *cơ chế cố định tốt nhất*, cùng mức evasion.

**v6 (corpus cũ, 40 flow, endpoint bar):**

| | evaded | +bytes | +pkts | mechs dùng |
|---|---:|---:|---:|---|
| fixed tốt nhất (`split8`) | 40/40 | +10.744 | +316 | 1 |
| **per-flow oracle** | **40/40** | **+9.792** | **+288** | **2** (`http_header_case`×14 zero-cost + `split8`×26) |

→ **STRICTLY Pareto-dominates**: không fixed mech nào đạt cùng evasion với
cost ≤ oracle. Đây là claim "RL adds something" **trung thực và đo được**:
per-flow selection tối thiểu chi phí tại cùng mức né, dùng **2 cơ chế khác
nhau** (đúng điều kiện ≥2 distinct actions cho claim "per-flow selection",
không phải "policy hằng số").

**v8 (corpus mở rộng, 5 flow HTTP, cả 2 bar):** oracle = `split8` fixed
(5/5, +1.224B/+36pkts) — **không có cost headroom**. Lý do: `http_header_case`
0/5 (T4.1), nên chỉ còn 1 cơ chế valid → không có gì để chọn rẻ hơn.

**Kết luận khoa học:** cost-axis headroom **có điều kiện theo corpus** — nó
tồn tại đúng khi có ≥2 cơ chế valid với cost khác nhau phủ các flow khác
nhau. Đây không phải artifact: nó là hệ quả trực tiếp của việc ruleset cũ
có rule case-sensitive (`2012627` FakeAV) mà ruleset mới trên flow mới thì
không (bắt bằng URL-content `2012533` thay vào đó).

### Đề xuất Phase 5 — RL trên trục chi phí (thay vì composite evasion)

Composite action space (Phase 4 theo MTO) giờ **không cần train**: 0 flow cần
phối hợp, nên nó sẽ chỉ tái xác nhận headroom=0 với chi phí ~12 ngày máy.
Thay vào đó:

1. **Reward có số hạng cost**: `r = valid_evasion − λ·wire_cost` (λ nhỏ, frozen
   trước). Policy học per-flow selection giữa các cơ chế valid.
2. **Baseline so sánh**: fixed mech tốt nhất (đã đo) + random policy + greedy
   cost-oracle (upper bound không học). Claim: RL tiến gần cost-oracle.
3. **Đo trên cả 2 corpus**: v6 (có cost headroom → RL phải thắng fixed) và
   v8 (không có → RL phải hội tụ về fixed, kiểm chứng không overfit).
4. **Không đổi bar, không đổi action space, không hạ ngưỡng** — chỉ thêm trục
   cost vào reward. Evasion metric giữ nguyên làm ràng buộc (constraint),
   cost là mục tiêu tối ưu.

Đây là hướng "thêm RL vào" **có tác dụng thật**: nó biến negative result
(evasion headroom=0) thành positive result (cost headroom>0, RL khai thác
được), mà vẫn trung thực với dữ liệu.

## Đo mới 2026-10-13 (thay đổi kế hoạch T0.3 và mẫu số)

Đo trực tiếp trên `ceiling_v4_both_test_dualbar.json` — **600 cell = 15 cơ chế ×
40 flow**, `conf: "default (ET Open full)"`, đã backfill **cả hai bar**. Tồn tại
`sids` (SID sót sau mutation) và `baseline_sids` trong từng cell → đủ để đo S1,
S2 và composite **không cần chạy lại Snort**.

| phép đo | kết quả |
|---|---|
| flow có `baseline_alert = True` | **40/40** |
| … nhưng sau khi loại SID P2P khỏi threat model (P11.6) | **16/40** |
| SID duy nhất xuất hiện trong 16 flow đó | **`2012627`** (FakeAV C2 check-in) |
| **GATE S1** (flow có ≥2 SID trong threat model) | **0** |
| phân bố số SID/flow | `{1: 16, 0: 24}` — không có ô 2 trở lên |
| `best_single` dưới `valid_evasion` | 40/40 = 100% |
| `best_single` dưới `valid_evasion_endpoint` | 40/40 = 100% |
| **composite headroom** (cả 2 bar) | **0** |

**Hai kết luận mới.**

**(a) Mẫu số đúng của threat model là 16, không phải 40.** 24/40 flow "cảnh báo"
chỉ vì SID `2008581/2008583/2008585` — BitTorrent DHT, đã loại ở P11.6. Trên
conf C2-only (`snort_et_c2_nop2p.conf`) phép đo lặp lại cho `n = 16`: `split8`
thắng **16/16**. Vậy câu "`best_single` = trần số học" vẫn đúng, nhưng phải nói
rõ **trên mẫu 16 có alert thật**, không phải 40. Mọi claim định lượng về `tỉ lệ
né` từ đây phải dùng mẫu 16 và nêu rõ nguồn.

**(b) T0.3 không cần chạy.** Dữ liệu 15 cơ chế × 40 flow trên full ruleset **đã
có sẵn**. T0.3 bị bỏ, thay bằng T0.3' (tái sử dụng). `ceiling_v6_case_fullrules`
(3 cơ chế × 40 flow, conf C2-filter) giữ làm **xác nhận độc lập** trên ruleset
thứ hai: `noop` 0/40, `split8` 40/40, `http_header_case` 16/40, không SID sống
sót. Hai ruleset, hai corpus-đo, cùng kết luận.

---

## Literature grounding (đọc đầy đủ, quote đã verify trong ledger)

### arXiv:2602.10299 — *The Role of Learning in Evading ML-based NIDS*

Thí nghiệm quyết định có ích cho ta: **horizon nhiều bước không phải thứ cần**.
Quote: *"one action already reaches everything the budget permits, and additional
actions expand nothing. Any advantage measured for H > 1 is therefore not a
horizon effect"*; *"At H = 1 the environment reduces to a contextual bandit"*.
Họ cũng chỉ trích nguyên văn: *"multi-step RL formulations are adopted without
first testing whether the problem is even sequential at all"*.

→ **Củng cố lựa chọn contextual-bandit của env.** Họ làm trong *feature space*
(cộng perturbation vào volume/duration NetFlow), ta làm trong *packet space* với
Snort — kết luận của họ **không tự động chuyển giao**, nhưng nó cho ta cơ sở để
bảo vệ thiết kế khi reviewer hỏi "sao không làm MDP nhiều bước".

→ **Thiếu sót ta phải bù:** §5.4.1 của họ chứng minh *"that mapping is not a
constant"* — tức policy thật sự điều kiện hoá theo flow, không sụp về một
perturbation cố định. **Ta chưa có phép thử này.** `headroom = 0` là phát biểu
tầng oracle, nó không nói policy đã train làm gì. Xem Task T4.2.

### arXiv:2510.14906 — *NetMasquerade*

Quote: *"we develop an RL framework that decides the location and type of packet
modification step-by-step"*. Action = **(packet nào, sửa gì)**. Có
*"effectiveness penalty, which safeguards the malicious functionality"* — cùng
tinh thần `sem_ok` của ta.

→ Ta thiếu **trục location**: env ta chỉ chọn *cơ chế nào*, áp lên **mọi** packet
có payload của client (`apply_mech`, `tgt_idx = pay_idx`). Đây là trục phải đo,
không phải trục phải thêm.

### IEEE 2025 — *Moving Target Offense: RL-based Adaptive Evasion Strategies for
C2 Frameworks* (Khamaisi, Crazzolara, Ristic, Brugger, Rodrigues, von der Assen,
Stiller — UZH/HSG)

**Đối thủ trực tiếp gần nhất, và nó làm đúng bài toán của ta**: RL evasion trên
C2 thật đối với **Snort**. NimPlant implant, Win10 → Ubuntu, tabular Q-learning,
100 episode/regime.

| | MTO | Env của ta |
|---|---|---|
| **State** | vector 7-bit ⇒ **2⁷ = 128 cấu hình** | 1 cơ chế |
| **Action** | bật/tắt 1 trong 7 chiến lược | chọn 1 cơ chế |
| IDS | Snort, naive + "expert" (6 rule tự viết) | Snort 2.9.20, ET Open 21.374 rule |
| Bar giữ ngữ nghĩa? | **không** — chỉ phạt alert + số chiến lược bật | `sem_ok`, `valid_evasion_endpoint` |
| So với best fixed? | **không** — chỉ so với implant chưa cấu hình | `oracle − best_single` |

Quote: *"expert rule evasion requires coordinated multi-strategy activation rather
than individual techniques"*; *"simple signature rules are bypassed once a small,
high-reward subset is found"*; *"becomes substantially more difficult as rule-set
complexity increases: under naive Snort rules the Q-Learning agent converges in
approximately 1 h"* (vs ~5,7 h expert).

**Ba hệ quả trực tiếp cho plan này:**

1. **Tiền lệ cho trục tổ hợp.** Agent họ đi trên không gian 128 cấu hình, tức
   chọn *tập hợp* chiến lược. Đó chính là thứ env contextual-bandit của ta không
   biểu đạt được, và là lý do T0.4 phải đo **headroom theo tập hợp cơ chế**.
2. **Họ không tính headroom.** Claim chính là RL thắng implant *chưa cấu hình*,
   không bao giờ so với tập cố định tốt nhất. Vì vậy kết quả dương của họ **không
   mâu thuẫn** với `headroom = 0` của ta; và `oracle − best_single` của ta mạnh
   hơn — **đó là đóng góp của thesis**.
3. **Trục tăng độ khó là rule complexity.** Họ đo được: ruleset đơn giản → một tập
   nhỏ là xong; ruleset phức tạp → phải phối hợp nhiều chiến lược, hội tụ chậm
   hơn 6×. Đây chính là lập luận cho Phase 1 + Phase 3, và nó **cũng** là lý do
   `headroom = 0` hiện tại là kết quả có giá trị chứ không phải thất bại.

**Điểm yếu của họ mà ta không có:** reward `r = 10 − k` / `−4·Σw − k` **không
hề kiểm tra kênh C2 còn sống** — không có bar giữ ngữ nghĩa. Đối chiếu với
arXiv:2505.01328 ("up to 80.3% invalid"). Khi cite phải nói rõ: họ là **tiền lệ
formalization**, không phải đối chiếu định lượng (n = 1 implant, ruleset 6 rule).

**Sửa claim khoảng trống học thuật.** Trước đây tôi ghi *"gần như không có
nghiên cứu nào so RL-evasion với Snort"*. **Sai — MTO chính là nghiên cứu đó.**
Khoảng trống đúng còn lại, thu hẹp lại: *chưa có nghiên cứu nào đo RL-evasion
bằng phép thử `oracle − best_single` trên ruleset thật, có bar giữ ngữ nghĩa*. Đây
mới là claim được bảo vệ được, và phải cite MTO là bối cảnh.

---

## Điểm mấu chốt: Gate S1 pass nhưng **dạng thoái lui**

Đọc `/tmp/cov/*/alert` gom SID theo 5-tuple (loại P2P): **5 flow có 2 SID**, đều
thuộc cặp `(2019471, 2019486)`. Đây **không phải** cơ hội headroom thật:

```
sid:2019471  alert tcp $EXTERNAL_NET any -> $HOME_NET any (... content:"PRIVMSG "; depth:8; pcre:"/^[^\r\n]*?\x3a...
sid:2019486  alert tcp $EXTERNAL_NET any -> $HOME_NET any (... content:"PRIVMSG "; depth:8; pcre:"/^[^\r\n]*?(?:p[ao]rt|udp|...
```

Cả hai rule đều là `to_client` — tức khớp payload **chiều server → bot**. Kẻ tấn
công không kiểm soát chiều đó. Các cặp khác (`2012533`/`2014169`,
`2012533`/`2014635`) không đồng thời xuất hiện trên một flow, và `2014169`
(`.su` TLD), `2016413` (DNS sinkhole) là rule **UDP/53** mà action phân mãnh /
HTTP header không áp dụng.

## Đã loại trừ: `headroom = 0` KHÔNG do độ phân cách của action

Giả thuyết đáng thử: env chỉ chọn 1 action cho cả một flow nên không mở được
headroom. Đã kiểm code và đo:

**Về code — giả thuyết ĐÚNG về cấu trúc:**
- `action_space = spaces.Discrete(N_ACTIONS)` (`hidden_defender_env.py:481`) —
  14 cơ chế, **không có chỉ số packet**.
- `apply_mech(pkts, mech, ...)` áp cơ chế lên `tgt_idx = pay_idx`, tức **mọi**
  packet có payload của client. Không có cơ chế nhắm packet con.
- `step(action)` (`:609`) gọi `score(flow, mech)` trên flow **nguyên**, rồi
  `self._idx += 1` — **không tích luỹ trạng thái**. Mỗi bước là một cặp
  (flow, cơ chế) độc lập.

→ Env là **contextual bandit**, không phải chuỗi quyết định. Policy **có thể**
chọn khác nhau theo flow ( nó quan sát `OBS_DIM = 11` trước khi hành động), nhưng
**không thể ghép nhiều cơ chế trên cùng một flow**.

**Về số — giả thuyết SAI, và đây là lý do:**

Đo trên `ceiling_v4_both_test_dualbar.json`, chỉ giữ flow có baseline alert:

| bar | flow có baseline alert | flow có ≥1 cơ chế đạt bar | flow **không** cơ chế nào đạt |
|---|---:|---:|---:|
| `valid_evasion` | 40 | **40** | **0** |
| `valid_evasion_endpoint` | 40 | **40** | **0** |

`best_single` = 40/40 = **100%** — bằng đúng trần. Không lựa chọn nào, ở bất kỳ
độ phân cách nào (theo flow, theo packet, hay ghép cơ chế), vượt được 100%.
`headroom = 0` ở đây là **hệ quả số học**, không phải giới hạn thiết kế của
action space.

**Nhưng cách nghĩ đó lộ ra một lỗ hổng thật của metric — và nó sẽ quan trọng
đúng lúc Phase 3 tạo ra ruleset khó hơn.** `rl_headroom.py` chỉ thử từng cơ
chế **đơn lẻ**; nó **về cấu trúc không thấy** trường hợp mà không cơ chế đơn nào
né được nhưng **tổ hợp** của chúng thì né được (ví dụ SID A nằm ở packet 1 bị
`split8` dập, SID B ở packet 5 bị `http_header_case` dập). Trên ruleset hiện tại
tập đó **rỗng** (0/40), nên `headroom = 0` là chứng minh. Trên ruleset khó hơn nó
có thể **không** rỗng — và khi đó `headroom = 0` chỉ là **chưa chứng minh**, đòi
phải đo thêm trước khi kết luận. Xem Task T0.4.

Vì vậy plan này dùng **hai gate**, không một:

- **Gate S1 (cấu trúc, đo trên traffic chưa mutate):** tồn tại flow có ≥2 SID
  **thuộc threat model**.
- **Gate S2 (hành động được, đo *thực nghiệm*):** trên flow đó, mỗi SID bị dập
  bởi ít nhất một action trong `ACTION_NAMES`, và **tập action dập SID này khác
  tập action dập SID kia**. Đây mới là điều kiện đủ cho headroom > 0.

S2 đo bằng cách chạy action thật, **không phân tích rule bằng regex** — đúng
triết lý "đo, đừng đoán" của toàn bộ P3–P12.

## Chống bias (điều kiện tiên quyết, không thương lượng)

Rủi ro lớn nhất của yêu cầu này: thử ruleset này, không được, thử ruleset khác...
cho tới khi tìm được bộ mà RL thắng → **benchmark thiên lịch**, kết luận khoa học
giả. Cách chặn:

1. Danh sách ứng viên ruleset **đóng băng trước** khi chạy bất kỳ phép đo nào
   (Task T3), kèm sha256.
2. Tiêu chí nghiệm thu là **S1 + S2 mang tính cấu trúc**, đo trên traffic
   **chưa mutate**. Không thể bị chọn lọc theo hành vi cơ chế.
3. Báo cáo **toàn bộ** ứng viên vượt S1, kể cả ứng viên cho `headroom = 0`.
   Không loại ứng viên nào vì nó cho headroom = 0.
4. Nếu không ứng viên nào vượt S2 → dừng, ghi negative result. **Không** hạ bar,
   **không** thêm action mới chỉ để mở headroom.

---

## Architecture

Ba tầng, mỗi tầng là một script read-only trên report, không đụng training:

```
snort_validation/reports/<corpus>.pkl
        │
        ├─ controls/ruleset_probe.py --conf name=path ...   (đã có, mở rộng)
        │     → per-flow SID list  (đo S1)
        │
        ├─ controls/sid_action_matrix.py                    (MỚI)
        │     → flow × SID × action: action nào dập SID nào  (đo S2)
        │
        └─ controls/rl_headroom.py --bar valid_evasion_endpoint
              --require-baseline                             (đã có)
              → headroom, oracle, best_single
```

`sid_action_matrix.py` là **artifact trung tâm**: nó trả lời trực tiếp câu hỏi
"các hướng tiếp cận cho action khác có đáng thử không", và là nơi duy nhất quyết
định có lên Phase 4 (RL) hay không.

---

## Step-by-step tasks

### Phase 0 — Đo nền (không tải gì, chưa đụng ruleset)

#### T0.1 — `controls/sid_diversity.py` + test (TDD)

Tạo `tests/test_sid_diversity.py` **trước**:

```python
# tests/test_sid_diversity.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))

from sid_diversity import summarize

P2P = {2008581, 2008583, 2008585}


def test_single_sid_flows_are_counted_but_not_multi():
    per = {"f1": [2012627], "f2": [2012627]}
    s = summarize(per, P2P)
    assert s["flows_alerting"] == 2
    assert s["flows_multi_sid"] == 0
    assert s["max_sids_per_flow"] == 1


def test_p2p_sids_are_excluded_before_counting():
    per = {"f1": [2008581, 2008583], "f2": [2012627]}
    s = summarize(per, P2P)
    assert s["flows_alerting"] == 1
    assert s["flows_multi_sid"] == 0
    assert s["excluded_p2p_sids"] == sorted(P2P)


def test_two_in_model_sids_on_one_flow_is_the_gate():
    per = {"f1": [2019471, 2019486]}
    s = summarize(per, P2P)
    assert s["flows_multi_sid"] == 1
    assert s["gate_s1_pass"] is True


def test_empty_input_is_not_a_pass():
    assert summarize({}, P2P)["gate_s1_pass"] is False
```

Chạy RED:

```bash
.venv/bin/python -m pytest tests/test_sid_diversity.py -q
# Expected: 4 failed  (ModuleNotFoundError: No module named 'sid_diversity')
```

Tạo `controls/sid_diversity.py`:

```python
#!/usr/bin/env python3
"""Summarise per-flow baseline SID lists into the Gate S1 decision.

Pure function over an already-measured {flow_id: [sid, ...]} mapping so it can
be unit-tested without Snort. P2P / BitTorrent DHT SIDs are removed *before*
counting: P11.6 established they sit outside the C2 threat model, and leaving
them in makes every flow look multi-SID.
"""
from __future__ import annotations

P2P_DEFAULT = frozenset({2008581, 2008583, 2008585})


def summarize(per_flow: dict, p2p_sids=P2P_DEFAULT) -> dict:
    """Return alerting/multi-SID counts and the Gate S1 verdict."""
    alerting, multi, seen_p2p = 0, 0, set()
    for sids in per_flow.values():
        kept = {s for s in sids if s not in p2p_sids}
        seen_p2p |= {s for s in sids if s in p2p_sids}
        if kept:
            alerting += 1
        if len(kept) > 1:
            multi += 1
    return {
        "n_flows": len(per_flow),
        "flows_alerting": alerting,
        "flows_multi_sid": multi,
        "max_sids_per_flow": max(
            (len({s for s in v if s not in p2p_sids}) for v in per_flow.values()),
            default=0,
        ),
        "excluded_p2p_sids": sorted(seen_p2p),
        "gate_s1_pass": multi > 0,
    }
```

Chạy GREEN rồi commit:

```bash
.venv/bin/python -m pytest tests/test_sid_diversity.py -q
# Expected: 4 passed
git add tests/test_sid_diversity.py controls/sid_diversity.py
git commit -m "feat(P13.0): sid_diversity.summarize - pure Gate S1 decision over measured SIDs"
```

#### T0.2 — `sid_action_matrix.py`: đo S2 bằng action thật

Tạo `tests/test_sid_action_matrix.py` trước:

```python
# tests/test_sid_action_matrix.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))

from sid_action_matrix import flow_headroom_from_cells


def test_same_action_set_on_both_sids_gives_no_headroom():
    # 2019471 and 2019486 are both killed by split8 -> nothing to choose between.
    cells = [
        {"flow_id": "f1", "mech": "split8", "baseline_alert": True,
         "baseline_sids": [2019471, 2019486], "evaded": True,
         "valid_evasion_endpoint": True},
    ]
    out = flow_headroom_from_cells(cells)
    assert out["headroom"] == 0
    assert out["reason"] == "identical action sets"


def test_disjoint_action_sets_create_headroom():
    cells = [
        {"flow_id": "f1", "mech": "split8", "baseline_alert": True,
         "baseline_sids": [2019471], "evaded": True,
         "valid_evasion_endpoint": True},
        {"flow_id": "f1", "mech": "http_header_case", "baseline_alert": True,
         "baseline_sids": [2019471], "evaded": True,
         "valid_evasion_endpoint": True},
        {"flow_id": "f1", "mech": "split8", "baseline_alert": True,
         "baseline_sids": [2019486], "evaded": True,
         "valid_evasion_endpoint": True},
    ]
    out = flow_headroom_from_cells(cells)
    assert out["headroom"] == 1
```

> Ghi chú cho implementer: `cells` ở trên là **ví dụ minh hoạ**, không phải dữ
> liệu thật. Một report thật chỉ ghi `baseline_sids`/`sids` ở cell `noop`, nên
> hàm phải nhận cả hai shape. Viết test cho **cả** shape thật lấy từ
> `snort_validation/reports/ceiling_v6_case_fullrules.json` (đọc 1 flow thật ra
> làm fixture) — nếu không, test sẽ xanh trên dữ liệu bịa và hỏng khi chạy thật.

Sau khi RED xác nhận, implement `flow_headroom_from_cells(cells)` trả
`{"headroom": int, "reason": str, "per_sid_actions": dict}`. Rồi viết
`build_matrix(cells, bar="valid_evasion_endpoint")` gom toàn report.

```bash
.venv/bin/python -m pytest tests/test_sid_action_matrix.py -q   # RED
# ... implement ...
.venv/bin/python -m pytest tests/test_sid_action_matrix.py -q   # GREEN
git commit -m "feat(P13.0): sid_action_matrix - per-SID action sets, the Gate S2 measurement"
```

#### T0.3 — ~~Chạy sweep 15 cơ chế~~ → **T0.3' Tái sử dụng dữ liệu đã đo**

**Bỏ.** Phép đo này đã tồn tại: `ceiling_v4_both_test_dualbar.json` (600 cell,
15 cơ chế × 40 flow, ET Open full, đã backfill cả hai bar). Chạy lại tốn ~2460 s
Snort mà không thêm thông tin. Thay bằng:

```bash
.venv/bin/python controls/sid_action_matrix.py \
  snort_validation/reports/ceiling_v4_both_test_dualbar.json \
  --out snort_validation/reports/sid_matrix_v7.json
```

Đối chứng vacuity **đã có sẵn, không cần chạy lại**: cell `noop` trong
`ceiling_v6_case_fullrules.json` cho `evaded = 0/40`, và trong v4 cho
`evaded = 0/40`. Hai ruleset độc lập cùng xác nhận.

Nếu sau này cần sweep trên conf mới thì dùng đúng lệnh gốc:

```bash
.venv/bin/python controls/ownership_ceiling_sweep.py --split test --ownership both \
  --mechs "noop,split8,split_slow,split16,split24,http_header_case,http_header_pad,corrupt8,length_wrapper,overlap8,pad16,prepend4,prepend8,prepend12,reorder,ttl" \
  --conf snort_validation/et_open_c2/snort_et_c2.conf \
  --out snort_validation/reports/ceiling_v7_full_matrix.json
```

**Gate P13.0:** `sid_matrix_v7.json` sẽ báo `gate_s1_pass = false` (đã biết từ
đo tay: SID duy nhất là `2012627`, `{1: 16, 0: 24}`). Ghi kết luận *"ruleset hiện
tại không thể tạo headroom dù thêm action nào"* vào
`docs/headroom_root_cause.md` rồi đi tiếp Phase 1. Đây **không phải** lý do dừng —
nó chính là lý do cần trục traffic.

#### T0.4 — `composite_oracle`: đo headroom mà metric hiện tại không thấy

`rl_headroom.py` chỉ thử từng cơ chế **đơn lẻ**. Trước khi kết luận
`headroom = 0` trên bất kỳ ruleset mới nào, phải biết có tồn tại flow mà
**không cơ chế đơn nào né được, nhưng tổ hợp của chúng thì né được** hay không.

Tạo `tests/test_composite_oracle.py` trước:

```python
# tests/test_composite_oracle.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))

from composite_oracle import composite_headroom


def _cell(fid, mech, sids, valid):
    return {"flow_id": fid, "mech": mech, "sids": sids, "valid_evasion": valid}


def test_no_single_mechanism_wins_but_pair_does_is_compositional_headroom():
    cells = [
        # split8 kills 2012627 but leaves 2014169; http_header_case the reverse
        _cell("f1", "split8", [2014169], False),
        _cell("f1", "http_header_case", [2012627], False),
    ]
    out = composite_headroom(cells)
    assert out["compositional_flows"] == ["f1"]
    assert out["composite_headroom"] == 1


def test_single_mechanism_already_wins_is_not_compositional():
    cells = [_cell("f1", "split8", [], True)]
    assert composite_headroom(cells)["compositional_flows"] == []


def test_all_flows_single_winnable_gives_zero_composite_headroom():
    cells = [_cell("f1", "split8", [], True), _cell("f2", "split16", [], True)]
    out = composite_headroom(cells)
    assert out["composite_flows"] == []
    assert out["composite_headroom"] == 0
```

Implement `composite_oracle.py` với `composite_headroom(cells, bar="valid_evasion")`:
theo flow, `best_single` = có cơ chế nào đạt bar không; `compositional` = không
cơ chế nào đạt bar **nhưng** tập SID còn sót của cơ chế tốt nhất rỗng khi hợp
nhất. Trả kèm `evidence` (flow + cơ chế + SID còn lại) để claim được kiểm chứng.

**Quan trọng — đây mới là chỗ env hiện tại không đạt được.** Env là contextual
bandit: `step()` không tích luỹ trạng thái, nên policy **không** dựng được tổ
hợp. Nếu `composite_headroom > 0`, thì **kết luận đúng** là *"headroom có
thật, nhưng action space hiện tại không biểu đạt được"* — và mở đường cho
thay đổi env. **Không** sửa env trước khi có số liệu.

**Định nghĩa phải bám theo MTO, không tự chế.** MTO đo trên **tập hợp** chiến
lược, không phải trên từng cơ chế. Vì vận `composite_headroom` phải được định
nghĩa là *"tồn tại tập hợp cơ chế `S` sao cho mọi cơ chế đơn lẻ đều **không**
đạt bar, nhưng `S` thì đạt"*. Cách kiểm chứng được, không phải suy đoán:

1. Với flow `f`, `A(f)` = tập SID còn sót của **hợp** các cơ chế đơn lẻ.
2. Nếu mọi cơ chế đơn lẻ đều **không** đạt bar ⇒ `f` là ứng viên compositional.
3. Trên ứng viên đó, dựng tập hợp tối thiểu dập hết `A(f)` bằng **thuật toán
   set-cover greedy trên quan hệ thực nghiệm đã đo** (SID nào bị cơ chế nào dập),
   rồi **kiểm chứng lại bằng cách chạy thật** tập hợp đó trên Snort.
4. Chỉ nếu bước 3 xác nhận mới tính là headroom.

Bước 3 là bắt buộc — set-cover trên dữ liệu đo là **giả định**, và action của
ta tương tác không tuyến tính (`split8` + `http_header_case` trên cùng flow có
thể khác với từng cái riêng). **Không** được báo headroom chỉ từ set-cover suy ra.

**Kết quả đo tay trên `ceiling_v4_both_test_dualbar.json` (2026-10-13):**

| bar | flow có baseline alert | flow có ≥1 cơ chế đạt bar | **ứng viên compositional** | **composite headroom** |
|---|---:|---:|---:|---:|
| `valid_evasion` | 40 | **40** | **0** | **0** |
| `valid_evasion_endpoint` | 40 | **40** | **0** | **0** |

→ Không có ứng viên nào để set-cover chạy. `composite headroom = 0` là **chứng
minh** trên ruleset này, không phải "chưa đo". Đây là baseline bắt buộc để khi
Phase 3 sinh ruleset khó hơn, ta biết `headroom = 0` ở đó **là** chứng minh hay
**chưa** chứng minh.

```bash
.venv/bin/python -m pytest tests/test_composite_oracle.py -q   # RED -> GREEN
.venv/bin/python controls/composite_oracle.py \
  snort_validation/reports/ceiling_v7_full_matrix.json \
  --out snort_validation/reports/composite_oracle_v7.json
git commit -m "feat(P13.0): composite_oracle - headroom from mechanism COMBINATIONS, invisible to rl_headroom"
```

**Kỳ vọng trên ruleset hiện tại: `composite_headroom = 0`** (vì 40/40 flow đã có
cơ chế đơn đạt 100%). Giá trị của task này là **thiết lập đường cơ sở** và bắt
lỗi metric, để khi Phase 3 sinh ra ruleset khó hơn thì biết `headroom = 0` ở đó
là chứng minh hay chưa chứng minh.

---

### Phase 1 — Đóng băng ứng viên ruleset (TRƯỚC khi đo gì)

#### T1.1 — Tải và kiểm tra toàn vẹn

```bash
mkdir -p rulesets/p13 && cd rulesets/p13
curl -sSL -o emerging-open-3.0.0.rules.tar.gz \
  https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz
sha256sum emerging-open-3.0.0.rules.tar.gz
```

Kiểm tra đã xác nhận được trước khi viết plan: URL trả **HTTP 200, 5 743 875
byte**. Ghi `sha256` vào manifest.

```bash
tar xzf emerging-open-3.0.0.rules.tar.gz
grep -cE '^\s*(alert|drop|pass|reject|log)\s' rules/*.rules
grep -oE 'sid:\s*[0-9]+' rules/*.rules | grep -oE '[0-9]+' | sort -n | sed -n '1p;$p'
# Ghi: so rule + khoang SID. So voi 21374 / 2000015-2102587 cua extract hien tai.
```

> **Không** `git add` file 30 MB. Chỉ commit manifest
> (`rulesets/p13/MANIFEST.md`) gồm URL, sha256, số rule, khoảng SID — đúng
> nguyên tắc P11.6 đã dùng cho ruleset 15 MB.

#### T1.2 — Đóng băng danh sách ứng viên

Tạo `docs/ruleset_candidates.md` với: URL, sha256, số rule, khoảng SID, và
câu trả lời cho *"cái gì khác nhau so với extract hiện tại"* — đặc biệt là các
SID chuyên bắt header evasion (`38381`, `38601`, `39320`) mà P12.7 ghi là
**vắng mặt** trong extract.

```bash
git add docs/ruleset_candidates.md rulesets/p13/MANIFEST.md
git commit -m "docs(P13.1): freeze ruleset candidates + manifest BEFORE any headroom measurement"
```

> Commit này là **bằng chứng chống bias**. Không được sửa danh sách sau khi thấy
> kết quả; nếu cần thêm ứng viên thì phải ghi lý do *trước khi* đo ứng viên đó.

---

### Phase 2 — Trục traffic (giá trị cao nhất, không tải gì)

#### T2.1 — Sao lưu `/tmp/cov` trước khi mất

`/tmp` **không sống sót reboot**. Đây là dữ liệu harvest tốn hàng giờ Snort.

```bash
mkdir -p data/stratosphere/alert_cov
for d in /tmp/cov/*/; do
  [ -f "$d/alert" ] && cp "$d/alert" "data/stratosphere/alert_cov/$(basename "$d").txt"
done
ls data/stratosphere/alert_cov | wc -l
# Expected: 15 (13 capture co alert + summary.txt)
```

```bash
git add data/stratosphere/alert_cov
git commit -m "data(P13.2): preserve harvested Snort -A fast alerts from /tmp/cov before reboot"
```

#### T2.2 — Mở rộng `SOURCES` của `build_corpus_v3.py`

`controls/build_corpus_v3.py` hiện liệt kê **4** capture. Bổ sung 4 capture có
SID thuộc threat model mà chưa có trong corpus lớn:

```python
SOURCES = [
    ("stratosphere", "botnet-capture-20110815-fast-flux",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-46/botnet-capture-20110815-fast-flux.pcap"),
    ("stratosphere", "botnet-capture-20110812-rbot",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-44/botnet-capture-20110812-rbot.pcap"),
    ("stratosphere", "botnet-capture-20110810-neris",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap"),
    ("stratosphere", "botnet-capture-20110815-rbot-dos",
     "data/stratosphere/CTU-13-Dataset/4/botnet-capture-20110815-rbot-dos.pcap"),
    ("cybersure-win", "capture-win13",
     "data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-55/capture-win13.pcap"),
]
```

> **Đường dẫn đã kiểm chứng** tại thời điểm viết plan (đừng tin tuyệt đối nếu
> dataset đã đổi — chạy `find` lại):
>
> | Capture | Đường dẫn thật |
> |---|---|
> | `botnet-capture-20110812-rbot` | `mcfp/CTU-Malware-Capture-Botnet-44/` |
> | `botnet-capture-20110815-fast-flux` | `mcfp/CTU-Malware-Capture-Botnet-46/` |
> | `botnet-capture-20110815-rbot-dos` | **`CTU-13-Dataset/4/`** — không nằm trong `mcfp/` |
> | `botnet-capture-20110816-donbot` | `mcfp/CTU-Malware-Capture-Botnet-47/` |
> | `capture-win13` | `mcfp/CTU-Malware-Capture-Botnet-55/` |
>
> `rbot-dos` nằm ở dataset khác (`CTU-13-Dataset`, không phải `mcfp`) — đoán
> đường dẫn theo số thứ mục sẽ hỏng.

> `capture-win13` có **911 flow** với SID `2016413` (DNS sinkhole). SID này là
> UDP/53 — **action phân mãnh HTTP không áp dụng**. Vẫn đưa vào corpus (để đo
> S1/S2 cho đủ), nhưng **không được** tính là ứng viên headroom nếu không có
> action nào dập được nó.

```bash
.venv/bin/python controls/build_corpus_v3.py \
  --alerts data/stratosphere/alert_cov \
  --out snort_validation/reports/hidden_defender_corpus_v4.pkl \
  --n-test 120
```

```bash
git commit -m "feat(P13.2): widen SOURCES to 5 alerting captures (rbot, rbot-dos, fast-flux, neris-20110810, win13)"
```

---

### Phase 3 — Lưới ruleset × traffic và quyết định

#### T3.1 — Chạy lưới, không chọn lọc

Với **mọi** cặp (ruleset ứng viên × corpus v3, v4), chạy sweep 15 cơ chế rồi
`sid_action_matrix`. Ghi kết quả vào `reports/sid_matrix_grid.json` — một bảng
duy nhất, đầy đủ, **kể cả các dòng cho headroom = 0**.

```bash
.venv/bin/python controls/sid_diversity.py --matrix snort_validation/reports/sid_matrix_grid.json \
  --out docs/sid_grid_table.md
git add docs/sid_grid_table.md
git commit -m "measure(P13.3): complete ruleset x traffic grid, including null results"
```

#### T3.2 — Gate quyết định

Viết vào `docs/headroom_root_cause.md` một mục `### P13.3`, nêu rõ:

- Ứng viên nào vượt S1, ứng viên nào vượt S2.
- Với ứng viên vượt S2: `headroom` đo được, và **tên flow + tên SID + tên action**
  cụ thể — không được chỉ nói "có headroom".
- Với ứng viên không vượt: lý do (chưa đủ SID? SID không actionable? mọi action
  dập cùng lúc?).

**Đây là điểm dừng bắt buộc.** Chỉ đi sang Phase 4 nếu **có ít nhất một** ứng
viên vượt S2 với `headroom > 0`.

---

### Phase 4 — RL (CHỈ chạy nếu Phase 3 mở headroom)

Không làm gì nếu gate đóng. Nếu mở, **thay đổi env phải theo MTO, không tự chế**:

MTO dùng **state = tập hợp đang bật, action = bật/tắt một cái** — `|S| = 2⁷`.
Đó là thay đổi rẻ nhất và có tiền lệ: `action_space` đổi từ
`Discrete(14)` (chọn 1 cơ chế) sang `MultiBinary(n_mechs)` (bật/tắt từng cơ chế),
giữ `step()` một lần trên flow đầy đủ đã mutate theo mask. **Không** biến env
thành MDP nhiều bước — arXiv:2602.10299 đã đo rằng horizon không phải thứ cần
và sẽ tốn thêm chi phí mà không mở được gì.

1. **`T4.1`** — Đưa `http_header_case` vào `ACTION_NAMES`
   (`ai_agent/hidden_defender_env.py`), kèm `--mechs` tương ứng trong
   `mech_applicable`. Commit riêng, có test.
2. **`T4.2` — Phép thử "policy có phải hằng số không"** (bắt buộc, theo
   §5.4.1 của arXiv:2602.10299). Tạo `controls/policy_is_constant.py` đo:
   entropy của phân phối action theo flow, và tỉ lệ flow mà argmax của policy
   khác cơ chế toàn cục tốt nhất. **Nếu policy luôn chọn một cơ chế thì báo
   `policy_is_constant = true`** — điều đó **đồng thuận** với `headroom = 0` và
   phải được nói thẳng. Tuyệt đối không viết *"RL đã học chọn theo flow"* khi
   phép thử này chưa chạy.
3. **`T4.3`** — Huấn luyện λ ∈ {0.3, 0.6} — **đúng ngưỡng đã đăng ký trước** ở
   `docs/action_space_policy.md`, không nới.
4. **`T4.4`** — Đối chiếu `RL ≥ best_single` trên **tập flow có detection**, không
   phải 40. Với mẫu số đúng đã xác định ở P13.0 (16 flow trên conf nop2p), báo
   cả hai: tỉ lệ trên **40 flow có baseline_alert** (gồm P2P) và trên **16 flow
   thuộc threat model**, ghi rõ mẫu số nào đang dùng.

---

## Tests / validation

| Kiểm tra | Lệnh | Kỳ vọng |
|---|---|---|
| Unit S1 | `.venv/bin/python -m pytest tests/test_sid_diversity.py -q` | 4 passed |
| Unit S2 | `.venv/bin/python -m pytest tests/test_sid_action_matrix.py -q` | passed, fixture lấy từ report thật |
| Đối chứng vacuity | `noop` trong `ceiling_v7_full_matrix.json` | `evaded = 0` trên **mọi** flow |
| Toàn vẹn report | `.venv/bin/python controls/verify_report_claims.py` | 109/109, exit 0 |
| Không regression | `.venv/bin/python -m pytest tests/ -q -p no:randomly` | không giảm so với baseline |

## Risks, tradeoffs, open questions

1. **Rủi ro lớn nhất — tải ruleset tạo headroom rồi kết luận "RL thắng".**
   Đây là benchmark thiên lịch. Cách chặn: S1+S2 mang tính cấu trúc, đo trên
   traffic chưa mutate, danh sách ứng viên đóng băng trước (T1.2). Nếu không
   giữ được, phần RL của plan này **không dùng được cho thesis**.

2. **`2019471`/`2019486` là cặp gần trùng.** Cùng `content:"PRIVMSG "`, cùng
   `depth:8`, cùng `to_client`, chỉ khác regex `pcre`. Khả năng cao mọi action
   dập cả hai cùng lúc → S2 fail với `reason="identical action sets"`. Đây là
   kết quả **hợp lệ và có giá trị**, phải ghi ra, không phải lỗi.

3. **`2019471`/`2019486` khớp chiều server → bot.** Kẻ tấn công không kiểm soát
   chiều đó. Nếu corpus định nghĩa `client` là chiều bot → server thì các rule
   này **không thể né bằng mutation client-side**, và mọi action sẽ báo
   `evaded = False`. Nếu sweep xác nhận điều này thì đó **không phải** bằng
   chứng fragmentation thua — mà là **cơ chế phát hiện nằm ngoài tầm với của
   kẻ tấn công**. Cần ghi rõ, vì nó là một phát hiện đáng kể về mô hình đe doạ.

4. **`/tmp/cov` không sống sót reboot.** Đã đưa T2.1 lên trước mọi thứ khác
   trong Phase 2 vì mất nó thì phải harvest lại từ đầu.

5. **Chi phí.** Sweep 15 cơ chế × 40 flow ≈ 2 h; × 120 flow ≈ 6 h; nhân với
   số ứng viên ruleset. Chạy nền (`background: true, notify: true`), nproc = 4.
   **Subagent không được chạy Snort hay full pytest** để không tranh CPU.

6. **`build_c2_only_ruleset.py` chỉ lọc theo classtype** (`--drop-classtype`,
   mặc định `policy-violation`). Ruleset mới có thể cần lọc sâu hơn; nếu vậy thì
   bộ lọc là **một quyết định thiết kế mới**, phải viết test và ghi vào docs —
   không sửa tay.

7. **Câu hỏi mở, không chặn Phase 0-2:** liệu có nên giữ P2P DHT như "rule
   thứ hai" để tạo lựa chọn giả không? **Không** — nó ngoài threat model
   (P11.6), và dùng nó để mở headroom là dựng benchmark. Nêu ở đây để không bị
   hiểu nhầm là một lựa chọn hợp lệ.

---

## Rủi ro kỹ thuật đã được kiểm tra rồi

| Kiểm tra | Kết quả |
|---|---|
| `curl` ET Open full | **HTTP 200, 5 743 875 byte** — tải được |
| `/tmp/cov` còn nguyên | **có**, 15 capture, alert files đọc được |
| SID theo capture (đọc từ alert file) | rbot/rbot-dos → 2 SID; neris-20110810 → 2 SID tách bạch; win13 → 911 flow / 1 SID |
| `ruleset_probe.py` có sẵn `--conf name=path` repeatable | có, đã dùng được cho lưới Phase 3 |
| `rl_headroom.py` có `--bar`, `--require-baseline` | có (T4, commit `f3063a8`) |

## Open questions cần implementer trả lời khi chạy

1. Trên `ceiling_v7_full_matrix.json`, `noop` có thật sự `evaded = 0` trên 40
   flow không? Nếu không → dừng, điều tra vacuity trước mọi thứ khác.
2. Có flow nào mà `split8` dập được SID A nhưng **không** dập được SID B trên
   chính flow đó? Đây là câu hỏi trực tiếp của Gate S2.
3. Các action HTTP (`split*`, `http_header_*`) trên traffic UDP/53 (`2014169`,
   `2016413`) trả về gì — `noop` hay lỗi? Nếu lỗi thì cần guard, vì win13 chiếm
   911/1193 flow và sẽ làm chậm mọi sweep.