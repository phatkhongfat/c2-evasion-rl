# Ứng viên ruleset — đóng băng trước khi đo (P13 Phase 1)

**Bằng chứng chống bias.** Danh sách này được chốt **trước** bất kỳ phép đo
headroom nào của P13. Số đo, sha256 và kết luận sơ bộ nằm ở
[`rulesets/p13/MANIFEST.md`](../rulesets/p13/MANIFEST.md).

## Vì sao cần ruleset mới

`headroom = 0` hiện tại đã được **chứng minh** trên `ceiling_v4_both_test` (600
cell, 15 cơ chế × 40 flow, cả hai bar): `best_single = 40/40` và
`composite headroom = 0`. Nguyên nhân đo được: **SID duy nhất là `2012627`**, mỗi
flow trong threat model khớp đúng **một** rule — không có gì để "chọn".

Thêm action không giúp (không có SID thứ hai để dập). Thêm rule chỉ giúp **nếu
rule mới cùng khớp một flow đã có rule khác**. Đó là điều ứng viên A nhắm tới.

## Ứng viên A — ET Open 3.0.0 (`emerging.rules.tar.gz`)

52 500 rule, 71 399 SID, khoảng 2000005–2527043. **Superset** của extract hiện
tại (21 374 rule, 2000015–2102587): cả 7 SID ta quan tâm đều còn, `2012627`
trùng khớp từng byte.

**Giới hạn đã biết trước khi đo:** không chứa `1-38381` / `1-38601` / `1-39320`
(SID bắt header evasion của ET Open full, namespace `1-xxxxx` nằm ngoài subset
*emerging*). Nên ứng viên A **không** nâng độ khó trên trục `http_header_case`.
Vẫn phải đo và báo cáo vì nó có thể mở SID thứ hai trên traffic mới.

## Ứng viên B — ET Open full

Không tải mới: `ceiling_v4_both_test` đã đo trên ruleset này. Giữ làm đối chiếu
độc lập với ứng viên A.

## Cổng quyết định

Ứng viên nào vượt **Gate S2** — tồn tại flow mà **mỗi SID bị dập bởi action
khác nhau**, hoặc tồn tại tổ hợp cơ chế mà không cơ chế đơn lẻ nào né được
(composite headroom, theo định nghĩa MTO) — thì mới sang Phase 4. Nếu không
ứng viên nào vượt: ghi negative result, **không** hạ bar, **không** thêm action
chỉ để mở headroom.