# Follow-up benign validation acceptance contract — NOT IMPLEMENTED
This contract does not rename the user's research topic. It isolates measurement validity from any evasion objective.
1. Local echo success: unique request ID and known benign bytes; independently observed matching response before monotonic deadline. Record endpoint_complete=true only on that observation.
2. Wrong response/ID: deliberately mismatched fixture; endpoint_complete=false with mismatch reason.
3. Deadline: no response fixture; endpoint_complete=false with timeout reason, distinct from mismatch.
4. Sensor failure: process crash/timeout or insufficient processing evidence => sensor status UNKNOWN/ERROR, never counted as a detector miss. Mock tests certify exception paths only; real integration remains NOT_RUN.
5. Artifact round-trip: serialize benign fixture then independently read it back; compare application content and declared translated fields against an explicit contract. Do not compare translated addresses with original addresses as if translation were forbidden. Capture input/output hashes.
6. Isolation: loopback only or separately approved isolated lab; no external egress, malware, or live C2. No network harness implemented by this document.
Record process exit, captured diagnostics, packet-processing counters where available, artifact hash, response evidence, deadline, and test result separately.
Known-positive detector fixture/configuration: NOT PROVIDED; real sensor positive/negative integration remains BLOCKED pending that fixture. Do not fabricate expected alert results.
Acceptance requires all observations from actual execution; an unexecuted case remains NOT_RUN.
