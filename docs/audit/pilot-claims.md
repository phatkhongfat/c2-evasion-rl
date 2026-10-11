# Claim mapping
- 40/40 split_slow: snort_validation/reports/ceiling_v3_splitslow_fixed.json; real_snort, ownership both, v3fixed theo tên artifact/context. Đây là fixed-mechanism sweep, không learned policy; semantics là offline predicate. Corpus/config hash của historical run chưa có: UNKNOWN.
- noop 0/40 valid và baseline 40/40: cùng report; đối chứng cùng scope, không chứng minh endpoint alive.
- PPO 99.2%, 127/128, 896 queries, 7 epochs trong README: historical replica run theo audit; KHÔNG được gán cho working-tree ppo_hidden_defender.json hiện tại (64 flows, real_snort). Giữ hai run phân biệt; không sửa report/verifier để khớp prose.
- Current training report evaded 638, n_flows 64: cumulative metric không phải final success numerator trên 64 flow; cần run log/definition trước sử dụng số này trong paper.
- Default corpus 1153 train/40 test: hidden_defender_corpus.json, same capture sources in train/test; không claim cross-capture generalization.
- Working C2 / live response / deadline: UNSUPPORTED by the offline report. Đề xuất wording: “Observed verdicts under the offline byte-equality predicate; independent endpoint functionality was not measured.”
- split8 100% toàn v3 / timeout là nguyên nhân đã chứng minh / PPO tốt hơn fixed baseline: chưa được chứng minh bởi report trên.
Gate A PARTIAL: snapshot hiện tại được hash, nhưng historical provenance không thể hồi tố bằng hash hiện tại. Không thay README hoặc số liệu.
