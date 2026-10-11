# Phase 3 measurement review
## Executed
Command: `.venv/bin/python -m pytest -q -p no:randomly tests/test_c2_semantics.py tests/test_evaluation_fixes.py::test_snort_failure_is_not_read_as_evasion tests/test_evaluation_fixes.py::test_snort_zero_exit_reads_flushed_alerts`
Observed: 7 passed in 1.41s; exit 0.
- test_non_overlapping_fragments_reassemble: synthetic bytes; literal expected byte oracle.
- test_overlap_first_and_last_disagree: synthetic bytes; explicit expected values for each policy.
- test_semantics_preserved_when_one_policy_recovers_original: synthetic bytes; existential offline recovery, not endpoint evidence.
- test_semantics_destroyed_when_no_policy_recovers_original: synthetic bytes; rejected mismatch.
- test_dht_ping_id_extracts_the_id_field: synthetic parser fixture; expected ID literal.
- test_snort_failure_is_not_read_as_evasion: mocked subprocess exit 1; RuntimeError expected.
- test_snort_zero_exit_reads_flushed_alerts: mocked subprocess creates two lines in a temporary alert file; expected count 2. This checks I/O handling, not realistic alert format or detector operation.
No real Snort launched by these selected tests; mock tests write temporary files. Normal interpreter/test caches may be written.
Remaining tests in test_evaluation_fixes.py and test_wire_deliverability.py: NOT_RUN in this phase; corpus/mutation/model-dependent, outside selected synthetic subset. No full-suite claim.
## Static trace (not runtime proof)
- eval_pipeline.py:431–436: original copied, optional mutation, semantics computed.
- eval_pipeline.py:438–442: translation, PCAP serialization, then detector invocation. No read-back semantics gate in this function.
- eval_pipeline.py:368–374: subprocess timeout configured; nonzero return raises. Timeout exception propagates here; caller-wide persistence not established.
- eval_pipeline.py:379–401: waits for alert files, counts nonempty non-comment lines. Missing alert files after successful exit yield zero. This alone does not prove detector failure OR healthy processing.
- eval_pipeline.py:443–454: verdict records counts/SIDs but not packet-processing counters, process stdout/stderr, or endpoint completion. Successful exit is not a packet-health measurement.
- c2_semantics.py:301–385: in-memory datagram comparison; 388–404 checks both streams. These are offline predicates, not socket/application observations.
## Verdict
PASS for selected unit assertions. PARTIAL for artifact validation: pre-serialization predicate differs from final artifact. UNKNOWN for actual detector processing health and endpoint completion in this pilot.
