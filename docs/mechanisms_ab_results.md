# Mechanisms A and B on real Snort — and a harness bug that invalidated earlier numbers

## What changed

| | before | now |
|---|---|---|
| `semantics_intact` | byte equality of the joined payload stream | the command a **real handler** would recover, per framing |
| action space | 12 mechanisms | 14 (`http_header_pad`, `length_wrapper`) |
| matrix scoring | 32 pairs per pcap | **1 pair per pcap** |

## 1. The corpus is not HTTP — it is half binary Neris

`snort_validation/corpus_framing_report.py`:

```
train  64 flows: http 32, neris 32
test   16 flows: http  8, neris  8
```

The 40 non-HTTP flows are Neris binary record chains
(`d1:ad2:id20:<20 bytes>:info_hash20:...`). Labelling them "http" — the
previous default — made `parse_command` return `None` for **41 of 80** flows,
and `None == None` makes *any* mutation look semantics-preserving. The
semantics bar was vacuous for half the corpus.

`endpoint_model.py` now detects framing and carries a `neris` parser.

**Honest limit:** the Neris record grammar was not reverse-engineered. The
parser only certifies that a stream *starts* as a record chain and otherwise
falls back to byte equality. For a protocol we cannot parse, only
byte-preserving mechanisms (fragmentation) count as safe. `append` is
therefore rejected on Neris, which is conservative — it is probably fine for a
length-prefixed protocol, but we do not claim what we did not verify.

## 2. Mechanism B cannot be measured on this corpus

No flow is length-prefixed (`length2`: 0/80). A wrapper header `LEN<n>:` makes
an HTTP flow unparseable and a Neris flow unparseable, so
`mech_applicable` reports **0/16** on the test split. B is provable by unit
test only. Reporting 0/16 as a negative result about B would be wrong.

## 3. A real Snort verdict bug — earlier numbers are not usable

Scoring 32 pairs in one pcap made Snort emit **4 alerts instead of ~32**, and
**12 of 32 verdicts disagreed** with scoring the same pair in its own pcap.
Every mismatching pair read "not detected" batched and "detected" alone.

This is not random: the matrix is *deterministic* and reproduced exactly
(0/224 differences across two runs), so batching silently understates
detection and the error looks stable.

Consequence: **every result measured with `batch_size=32` is void** — that
includes the 100% evasion run and the 90.6% baselines already retracted, and
would have included the new numbers. The matrix now scores one pair per pcap
(224 snort calls, ~10 s each), and
`tests/test_snort_verdict_integrity.py` pins both the tripwire and the
isolated-by-default fix.

## 4. Mechanism A

Junk goes into HTTP **headers**, never in front of the request line and never
into a binary record chain. Two bugs found while building it:

- an extra `\r\n` after the junk block terminated the header section early,
  so the body changed and the command was lost;
- `fix_checksums` edited only `Raw.load`, leaving a pre-existing `Padding`
  layer in place — rebuilt bytes re-parsed into a 20-byte tail.

`fix_checksums` now replaces the whole payload stack under the transport and
rebuilds from the packet's own link-layer class (re-parsing as `IP()` dropped
the Ethernet header on `Ether/IP/TCP` corpus packets).

## Results

<!-- FILLED IN AFTER ISOLATED SCORING COMPLETES -->
