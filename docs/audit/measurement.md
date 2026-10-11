# Measurement audit
Confirmed scope gap (P0 for live-functionality claims): eval_pipeline.py:436 checks semantics BEFORE translation and PCAP serialization (:438–440). Output score :443–454 has no independent endpoint response/deadline evidence.
c2_semantics.py:329–385 assembles consecutive fragments and compares datagram counters; :388–404 compares both recovered streams. This is a static predicate, not OS/application delivery. No timeout-based endpoint validation appears in that predicate.
Positive: eval_pipeline.py:372–374 raises on nonzero Snort exit. Crash is not automatically converted into no-alert in that branch.
Unknown: successful process plus missing alert file can mean legitimate zero alerts or insufficient processing; return schema does not expose processing statistics. Need health evidence before classifying absence of alert, not blanket rejection of missing files.
Final serialized artifact correctness remains unproven here; compare against expected translated baseline, not raw byte identity with untranslated original.
No network tests, traffic generation, Snort sweep or remediation performed.
