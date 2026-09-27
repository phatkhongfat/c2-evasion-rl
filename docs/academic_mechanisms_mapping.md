# Academic Evasion Mechanisms vs. Network C2 + Real Snort

User referenced three academic papers on evasion. This doc evaluates which transfer to the network-level C2 problem (Snort IDS).

## 1. Semantic NOP Insertion (arxiv 2009.05602)

**Original (binary):** Add dummy mathematical operations that alter the Control Flow Graph (CFG) but don't change program behavior. Goal: fool Graph Neural Networks (GNNs) trained on CFGs.

**Network transfer:** Add dummy packets or junk traffic that does not alter C2 semantics but changes traffic shape.

**Applicable to Snort?** Partially, and low-value.
- Snort rules match on payload content/structure, not traffic graph topology.
- A dummy packet carrying no C2 command is still dropped by a valid C2 server.
- Mechanism `noop` (keep TTL = 33) achieves signal-level mutation without changing payload; it evaded in isolated tests but likely because Snort's frag3 reassembly is permissive.
- **Takeaway:** junk packets alone are insufficient; the C2 semantic must survive.

## 2. Instruction Substitution & Code Transposition (mdpi 2076-3417/15/22/12015)

**Original (binary):** Replace `xor eax, eax` with `sub eax, eax` (semantically identical), or reorder instructions with no dependencies.

**Network transfer:**
- **Protocol substitution:** Replace semantically equivalent operations, e.g., HTTP `GET` with `POST` if the server accepts both for the same command.
- **Packet reordering:** Reorder non-dependent packets in a C2 stream.

**Applicable to Snort?** Yes, and already partially implemented.
- Mechanism `reorder` (swap packets 1 and 2) is a form of instruction transposition. It evaded on test set (16/16).
- Protocol substitution requires **protocol-specific knowledge** (which alternatives are equivalent). Current setup uses only HTTP/IRC/Neris, and HTTP GET/POST both carry command in the body, so they are interchangeable — but this is not implemented.
- **Takeaway:** reordering is cheap and works; protocol substitution would need domain modeling per C2 family.

## 3. Traffic Morphing (intechopen/chapters/1231530)

**Original (network):** Pad packets or introduce delays to alter packet-length and timing signatures. Preserves semantic payload.

**Applicable to Snort?** Yes, fully implemented and most effective on HTTP.

Mechanisms already covering this:
- **Padding:** `pad16`, `prepend8/12`, `overlap8` (prepend creates a preamble that breaks the handler, so only `pad` is safe).
- **Fragmentation:** `split8/16/24` (break one datagram across multiple IP fragments).
- **Protocol-aware padding:** `http_header_pad` (insert junk headers that a real HTTP server skips).
- **Wrapper with offset:** `length_wrapper` (encapsulate with a header that declares where real data starts).

Results on HTTP-only test set (8 flows, **evaluated with real Snort, batch_size=1**):
- Awaiting completion of `eval_all_real_snort.py` (currently 9/112 pairs scored).

## Summary

| Category | Mechanism | Status | Notes |
|----------|-----------|--------|-------|
| NOP insertion | dummy packets | no | Breaks C2; low SNR |
| Instruction subst. | packet reorder | ✓ yes | Evaded 16/16; cheap |
| Protocol subst. | HTTP GET↔POST | not yet | Needs domain model |
| Traffic morphing | padding | ✓ yes | `pad` safe; `prepend` breaks handler |
| | fragmentation | ✓ yes | `split` 8/16/24 all evade |
| | protocol-aware padding | ✓ yes | `http_header_pad` on HTTP only |
| | wrapper offset | ✓ yes | `length_wrapper`, N/A on corpus (no length2 flows) |

## Open: Why only split variants?

User asked: "có cách nào không thể cứ split tất cả mọi thứ như thế được" (is there a way other than split?).

Answer: No, split is not the only way. The 14 mechanisms include:
1. Fragmentation (split8/16/24, overlap8)
2. Padding (pad16, prepend8/12)
3. Protocol-aware padding (http_header_pad)
4. Wrapper (length_wrapper)
5. Reordering (reorder)
6. Metadata (ttl, noop)

All but prepend/pad/corrupt/overlap evaded on the strict byte-equality bar. On HTTP specifically, `http_header_pad` and `length_wrapper` are novel because they **change wire bytes while preserving semantics** — unlike fragmentation, which preserves bytes by construction.

## Next: per-flow heterogeneous defender

A single static evasion recipe (e.g., "always split8") generalizes to all flows because they share the same Snort config. The recommended next step is to defend by **varying reassembly policy per flow** (e.g., frag3 policy = `last`, `first`, `drop_overlaps`, etc.), so an attacker cannot memorize one trick that works for all.
