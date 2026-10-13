# Plan: Giá trị học thuật vượt ra ngoài “oracle = một action”

## Goal

Đánh giá trung thực tính khả thi, độ tin cậy và giới hạn của benchmark hiện tại; chỉ nghiên cứu lợi ích của adaptive decision-making trong một benchmark tài nguyên lành tính độc lập, không phát triển policy né IDS.

## Scope và ranh giới

Plan này KHÔNG triển khai action mới, mask để né Snort, tối ưu C2, tìm traffic có thể bypass, sweep hay retrain evasion agent. Chỉ audit các artifact hiện có và thiết kế thí nghiệm ML lành tính. Không chạy script của project chỉ để đọc JSON: một số script ghi report hoặc gọi scorer.

Workspace: `/root/.hermes/c2-evasion-rl`.
Chỉ plan này được ghi trong turn lập kế hoạch. Các đường dẫn tài liệu dưới đây là deliverable của một turn thực thi được phê duyệt sau, không phải file đã tồn tại.

## Current context / assumptions

- `docs/rl_substantive_claim.md` là verdict trước đó, không phải ground truth. Có suy luận nhân quả và nhận định chi phí cần audit lại.
- Các matrix hiện có nằm trong `snort_validation/reports/`.
- Đã đọc trực tiếp `div_probe.json` trong turn này: 96 rows, 12 flow IDs, baseline positive 8, baseline negative 4, không thấy baseline bất nhất trong cùng flow.
- Vì vậy phát biểu “12/12 evasion” trước đó không phải một ước lượng hợp lệ trên 12 positive examples. Bốn baseline-negative flows phải được báo riêng; không được tính là né thành công.
- Nhiều winner-set khác nhau không đồng nghĩa với oracle tốt hơn mọi constant policy. Các tập có thể cùng chứa một action.
- Equality trên một corpus hữu hạn không chứng minh giới hạn của mọi corpus hoặc mọi thuật toán.
- Hai lần shaping không tạo diversity chỉ hỗ trợ kết luận về các lần chạy đó; chưa phân biệt đầy đủ nguyên nhân do dữ liệu, observation, optimizer hoặc ngân sách.
- Byte equality là phép kiểm tra trên biểu diễn dữ liệu, không tự chứng minh ứng dụng ở endpoint vẫn hoạt động, độ trễ chấp nhận được hoặc traffic đi được qua môi trường triển khai.
- Không giả định split8 là action rẻ nhất: cần đối chiếu cost trong source và phân biệt hệ số reward do người viết đặt với chi phí đo thực tế.

## Trả lời giả thuyết “split8 không khả thi”

Có ba câu hỏi khác nhau:
1. **Bị cấm toàn cục:** loại lựa chọn đó khỏi mọi phương pháp; một lựa chọn cố định khác vẫn có thể tối ưu. Không tự suy ra lợi thế RL.
2. **Không khả thi theo context:** adaptive selection có thể hữu ích, nhưng baseline phải biết cùng context và cùng tập lựa chọn hợp lệ. Một rule-based selector đơn giản có thể đủ.
3. **Không khả thi vì trạng thái tài nguyên phụ thuộc hành động trước:** mới có lý do nghiên cứu quyết định tuần tự. Vẫn phải so với greedy, contextual bandit và heuristic có trạng thái.

Ràng buộc phải có nguồn độc lập với kết quả mong muốn: yêu cầu vận hành, quota, SLA, năng lực endpoint hoặc chính sách đã có trước. Không mask action thắng chỉ để tạo một benchmark RL thắng. Không chọn constraint sau khi nhìn test labels.

## Architecture / proposed approach

Tách hai đóng góp: (A) audit độ tin cậy và phạm vi claim của kết quả hiện có; (B) nếu cần đóng góp RL, nghiên cứu phân bổ tài nguyên trên job lành tính không liên quan packet/C2/IDS. Khóa objective, constraints, baselines và data split trước khi thực nghiệm; dùng gate để cho phép kết quả “heuristic/bandit đủ dùng” thay vì bắt buộc RL thắng.

## Hướng tiếp cận và ưu tiên

### A — Benchmark-validity paper/chapter (khuyến nghị làm trước)

Đóng góp: chỉ ra cách baseline coverage, applicability, provenance và endpoint-validity làm thay đổi cách diễn giải một con số cao. Dùng artifact đã có; không cần chạy thêm chiến dịch evasion. Có giá trị ngay cả khi adaptive policy không tốt hơn constant policy.

### B — Feasibility/robustness study (mô tả và audit)

Phân biệt không có alert, đúng bytes, thực thi được và đạt mục tiêu ứng dụng. Nếu chưa có bằng chứng endpoint hoặc deployment constraint, ghi UNKNOWN chứ không gán TRUE. Không cung cấp quy trình bypass để bổ sung bằng chứng.

### C — Resource-constrained decision-making trên workload lành tính

Ví dụ: chọn chạy, hoãn hoặc từ chối job xử lý dữ liệu dưới quota CPU và deadline. Hành động hôm nay thay đổi queue/budget ngày mai. Đây là benchmark mới, kết quả không được dùng như chứng cứ RL vượt fixed cho C2.

### Không chọn

- Tắt bar để tăng headline.
- Loại winner tùy ý để tạo headroom.
- Chọn test set theo nhãn “action thắng” rồi claim tổng quát hóa tự nhiên.
- Đổi utility sau khi thấy ai thắng.
- Claim RL cần thiết chỉ vì policy dùng nhiều action.

## Step-by-step tasks

Mỗi task dưới đây là 2–5 phút làm việc tập trung; các lần chạy thí nghiệm mới KHÔNG nằm trong phạm vi plan này. Các phase audit không có code production nên không tạo RED/GREEN giả. Không commit trong turn lập kế hoạch.

### Phase 0 — Freeze câu hỏi và scope

**0.1 — Snapshot read-only.**

```bash
cd /root/.hermes/c2-evasion-rl
git rev-parse HEAD
git status --short
```

Expected: ghi lại SHA thực tế và danh sách dirty/untracked. Không yêu cầu tree sạch, không stash/reset. Ghi snapshot vào `docs/academic_value/provenance.md` trong turn thực thi.

**0.2 — Claim ledger.**

Tạo `docs/academic_value/claim_ledger.md` với các cột: claim; artifact; điều kiện; measured/inferred/unknown; limitation; allowed wording. Phải có các dòng: P3 matches ceiling; shaping không tạo diversity; client/mixed headroom; probe baseline coverage; cost ordering; endpoint validity.

Acceptance: không dùng “pipeline đúng hoàn toàn”, “RL không có lỗi” hoặc “nguyên nhân chắc chắn là SID geometry” chỉ từ một score.

**0.3 — Report Phase 0.**

Báo SHA, phạm vi audit và những claim đang treo; không launch trainer hoặc sweep.

### Phase 1 — Audit probe bị thiếu baseline coverage

**1.1 — Re-derive baseline coverage bằng JSON thuần.**

Lệnh read-only hoàn chỉnh:

```bash
cd /root/.hermes/c2-evasion-rl
python3 -c 'import json; from pathlib import Path; d=json.loads(Path("snort_validation/reports/div_probe.json").read_text()); rows=d["cells"]; ids={r["flow_id"] for r in rows}; b={f:{r["baseline_alert"] for r in rows if r["flow_id"]==f} for f in ids}; print({"rows":len(rows),"flows":len(ids),"baseline_positive":sum(v=={True} for v in b.values()),"baseline_negative":sum(v=={False} for v in b.values()),"inconsistent_baseline":sum(len(v)!=1 for v in b.values())})'
```

Expected cho artifact đã inspect: rows=96, flows=12, positive=8, negative=4, inconsistent=0. Nếu khác: ghi kết quả mới và provenance; không sửa data để khớp.

**1.2 — Sửa phạm vi diễn giải, không sửa raw report.**

Viết `docs/academic_value/baseline_coverage.md`: probe là exploratory, không đủ để khẳng định 12 valid-positive examples. Không nói “noop control pass”: probe không chứa noop, thiếu control phải ghi MISSING, không phải zero successes.

**1.3 — Audit cấu trúc matrix.**

Đọc `div_probe.json`: kiểm tra duplicate `(flow_id, mech)`, tập action có đồng nhất mỗi flow, bool có đúng kiểu, trường missing. Chỉ ghi evidence; không tự fill missing cells thành thất bại hoặc thành công.

Acceptance: toàn bộ flow được phân nhóm positive/negative/inconsistent/unknown; tổng khớp số IDs. Đừng suy luận causality từ chỉ timestamp commit.

**1.4 — Report Phase 1.**

Nêu rõ claim cũ nào cần rút lại và claim nào vẫn giữ được. Không biến integrity failure thành bằng chứng adaptive policy có lợi thế.

### Phase 2 — Constraint validity và fairness

**2.1 — Viết `docs/academic_value/constraint_contract.md`.**

Mỗi constraint cần đầy đủ: tên; nguồn độc lập; đơn vị; hard/soft; global/contextual/stateful; được biết lúc quyết định hay không; áp cho ai; có evidence không. Thiếu evidence thì gắn hypothetical và chỉ dùng trong sensitivity analysis, không gọi deployment-realistic.

**2.2 — Khóa quy tắc so sánh.**

Trong cùng file, ghi:
- Mọi contender chịu cùng action availability, quota, deadline và observation.
- Không cho RL nhận thông tin outcome/test labels mà baseline không có.
- Khi fixed action unavailable, định nghĩa fallback trước. So cả fixed-with-fallback và context-aware heuristic; không chỉ so với baseline bị vô hiệu hóa.
- Best comparator được chọn trên validation; test oracle chỉ là upper bound hồi cứu, không phải policy deployable.
- Nếu không lựa chọn nào khả thi: báo abstain/unserved, không loại job khỏi denominator để tăng score.

**2.3 — Chọn objective trước khi nhìn test.**

Đối với benchmark job lành tính: primary là fraction jobs hoàn thành đúng hạn dưới quota; secondary là CPU-time, latency, tỷ lệ từ chối và constraint violations. Hard constraints được báo riêng, không bị che bởi weighted reward.

Acceptance: có một primary metric, một denominator cố định, nguồn của mỗi constraint và quy tắc fallback rõ ràng.

**2.4 — Report Phase 2 / gate C.**

Nếu chỉ có giả định “cấm action thắng”, verdict là hypothetical ablation, không claim thực tế. Nếu có context-dependent constraints nhưng không có dependence giữa các quyết định, ưu tiên supervised selector/contextual bandit, chưa dùng RL.

### Phase 3 — Thiết kế benchmark tài nguyên lành tính (không triển khai)

**3.1 — Viết `docs/academic_value/benign_benchmark_protocol.md`.**

Schema job: `job_id`, `workload_group`, `arrival_time`, `input_size`, `deadline`, `estimated_cpu`, `realized_cpu`, `completion_time`. `realized_cpu` và `completion_time` là outcome, không observation khi ra quyết định. Không packet payload, ruleset, SID, PCAP hoặc model evasion trong schema.

**3.2 — Baselines.**

Danh sách khóa trước: constant/default feasible strategy; FIFO; earliest-deadline-first; greedy cost-aware; contextual bandit; RL chỉ khi task stateful. Cùng compute/tuning budget. Offline oracle chỉ dùng cho bài toán scheduling lành tính với thông tin tương lai, luôn gắn nhãn non-deployable.

**3.3 — Split và statistics.**

Split theo workload group và thời gian trước khi chọn model; không có cùng job hoặc duplicate input qua hai split. Chọn hyperparameter trên validation; khóa test một lần. Báo mọi seed đã đăng ký, paired differences, uncertainty theo group độc lập; không coi job cùng trace hoặc nhiều seed trên cùng test trace là dataset độc lập.

Ngưỡng practical significance phải được chủ sở hữu workload xác lập trước. Nếu chưa có threshold, verdict là exploratory; không invent threshold để công bố thắng.

**3.4 — TDD contract cho implementation sau này.**

Các path dự kiến, chưa tạo trong plan turn:
- `tests/test_benign_scheduling_contract.py`
- `benchmarks/benign_scheduling/contract.py`

Test specification: unavailable choice không thực thi; quota không âm; hết choice thì abstain; cost/latency đúng đơn vị; không observation leakage; mọi baseline nhận cùng mask; deterministic replay theo seed; split groups disjoint. Implementer phải viết từng test → chạy thấy fail đúng assertion/import → implement tối thiểu → chạy pass → review/commit từng đơn vị. Không tạo module giả rồi tuyên bố benchmark hoàn tất.

Vì đây là design-only phase, code implementation và command runner phải nằm trong một plan tiếp theo sau khi contract được duyệt; không giao cho implementer tự đoán semantics.

**3.5 — Report Phase 3 / gate R.**

Nếu greedy đạt cùng kết quả hoặc chưa có sequential dependency: không triển khai RL. Nếu dependency thực và baseline chưa đủ: đề xuất experiment budget riêng, không tự launch.

### Phase 4 — Verdict và tài liệu bài

**4.1 — Viết `docs/academic_value/verdict.md`.**

Ba verdict độc lập:
1. Existing security results: độ tin cậy/phạm vi của evidence cũ; missing provenance và endpoint validation.
2. Constraints: measured/hypothetical/unsupported.
3. Benign decision benchmark: design-ready/not-ready; chưa có outcome thực nghiệm.

**4.2 — Allowed claims.**

Có thể viết: “Trên tập đo và action set được xét, một constant policy đạt cùng upper bound của metric; kết quả chưa chứng minh lợi ích adaptive selection.”

Nếu chưa đo deployment feasibility: viết “chưa được xác nhận”, không viết “thành công C2 trên môi trường thực”.

Nếu benchmark benign sau này thắng: chỉ claim lợi ích trên workload/quota đã đăng ký; không chuyển kết quả đó sang claim bypass IDS.

**4.3 — Review checklist.**

Reviewer kiểm tra: mọi số trace tới artifact; không lấy 0/0 làm pass; không coi 8/12 baseline coverage là 12 positives; không đổi baseline sau test; không kể causal story khi chỉ có correlation; không ép diversity làm objective thay task utility.

**4.4 — Commit ở turn thực thi, sau review.**

Chỉ stage từng file mới dưới `docs/academic_value/`; không `git add .`, không stage untracked scripts/reports khác. Kiểm tra `git diff --cached --stat` trước commit. Commit không bao gồm trainer, packet mutator, ruleset hoặc checkpoint.

## Tests / validation

Audit turn chỉ đọc artifact, không chạy Snort và không training. Kết quả expected duy nhất được khóa trong plan là coverage của artifact đã inspect; chưa có expected win của thuật toán. TDD dành cho benchmark benign sau khi protocol được duyệt, không giả một regression pass từ test count suy ra.

## Risks, tradeoffs, open questions

- Chọn corpus theo winner labels rồi dùng cùng cách chọn trên test có thể tạo selection bias. Giữ natural-distribution holdout và gắn exploratory cho enriched set.
- Cấm duy nhất một action đang thắng là ablation, không phải chứng minh nhu cầu RL.
- Ràng buộc theo context có thể tạo headroom nhưng không bảo đảm RL tốt hơn heuristic/bandit.
- Success ceiling bằng nhau vẫn có thể để lại khác biệt cost hoặc sample efficiency; cần đo đúng đơn vị, không dùng reward coefficient như measured cost.
- Replay preserving bytes không thay endpoint evidence.
- Câu hỏi còn mở: bài hướng security measurement hay generic sequential decision-making? Mặc định plan ưu tiên security measurement (A), benchmark benign (C) là nhánh riêng chỉ thiết kế, không thay chủ đề âm thầm.
- Không thể cam kết đủ chuẩn một venue hoặc hội đồng từ vài score. Giá trị học thuật cần literature positioning, threat-to-validity và independent review.

## Done criteria

Có provenance, claim ledger, baseline-coverage audit, constraint contract, benign benchmark design và verdict phân biệt measured/hypothetical. Không thêm capability evasion; không claim RL beats fixed nếu chưa có một comparison công bằng và evidence độc lập.
