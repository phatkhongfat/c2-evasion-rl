# Pilot result — Phase 1–4 (limited measurement audit)
## Gates
A — PARTIAL: 10 source/config/report files frozen with SHA256 and working-tree context; historical-run provenance remains unknown. Current hashes must not be backdated as historical evidence.
B — PASS diagnosis: identified Python3.11 runtime vs Python3.12 bare-pip target; correct-interpreter pip works. `python -m pip check` passed. Declared dependency mismatch is not a proven package incompatibility.
C — PASS for pilot documentation/test-selection gate only: selected synthetic and mocked-process tests returned 7 passed in 1.41s (exit 0). See pilot-test-matrix.md and pilot-validation-spec.md. Artifact read-back validation remains PARTIAL; real detector health and endpoint completion remain UNKNOWN. No full-suite, live endpoint, training, or real-Snort validation claimed.

## Phase 3–4 completion
Static trace confirms semantics is evaluated before translation/serialization. Nonzero sensor exit raises; missing alert output after successful exit becomes zero without persisted packet-health evidence in this scorer. This is an evidence gap, not proof all zero-alert results are invalid. Existing 40/40 result was not rerun or invalidated by this pilot. Follow-up benign acceptance contract is specified, not implemented. Source and environment unchanged; only audit documentation updated (ordinary pytest caches/temp files excepted).

Next priorities: (1) separately implement the benign artifact/endpoint contract, with observed response and deadlines; (2) establish real sensor-health/known-positive integration evidence; (3) preserve future run-specific provenance. Until then, use offline-scoped wording only. These measurement recommendations do not redefine the user's research topic.

## No behavioral changes
No source/config/report edits outside docs/audit. No dependency install/upgrade, training, Snort run, network traffic, cleanup or commit. Manifest verification performed separately.

## Three next actions
1. Approve wording/provenance changes for README and preserve run-specific reports (hours; must not rewrite results to fit narrative).
2. Continue Phase 3 benign measurement checks (separate static/artifact/endpoint verdicts); this establishes what the existing result actually measures, not stronger evasion.
3. Only if reproduction required, approve a fresh isolated environment, with explicit version target (current snapshot vs intended pins), not in-place repair.

Bottom line: môi trường chưa được chứng minh là hỏng; vấn đề chắc chắn là hai đường installer/runtime khác nhau và documentation không khớp. Research claims vẫn cần thu hẹp theo bằng chứng offline.
