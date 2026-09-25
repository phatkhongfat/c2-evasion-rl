# Dataset & Ruleset Switch: Stratosphere IPS + ET Open C2

**Date:** 2026-09-25
**Status:** in progress

## Why this change

The project's earlier results rested on two things that made the "defense" a
mirror of the reward rather than an independent judge:

1. **Hand-written rules.** `snort_validation/rules/botnet-behavior.rules` and
   `botnet-aggressive.rules` were authored in this repo. Their thresholds were
   reverse-engineered from the same flow aggregates (`dur`, `tot_bytes`,
   `tot_pkts`, `src_bytes`) that the agent's features come from. A detector
   built from the features it is supposed to judge cannot tell you whether the
   agent generalises to a real IDS.

2. **Synthesised traffic.** Flows were replayed by
   `snort_validation/flow_to_pcap.py`, which fabricates packets to match six
   aggregate statistics. Any rule matching on payload content, TCP flags, or
   packet timing could never fire, because that information was never present
   in the first place.

Both are replaced here with third-party artifacts:

| | Before | After |
|---|---|---|
| Traffic | synthesised from 6 aggregates | real captured pcaps (Stratosphere IPS / CTU-13) |
| Rules | hand-written in this repo | ET Open, filtered to a C2 subset |
| Rule provenance | same author as the reward function | Emerging Threats (independent) |

## 1. Dataset: Stratosphere IPS (CTU-13)

**Publisher.** Stratosphere IPS, the lab of Sebastián García at CTU in Prague.
The Stratosphere IPS project is the publisher of the CTU-13 botnet capture
dataset; `mcfp.felk.cvut.cz` is their official distribution host. The
Stratosphere site (`stratosphereips.org/datasets-ctu13`) links directly to it.

**Artifact.** `CTU-13-Dataset.tar.bz2` — 1,905 MB, 13 malware captures
(1-Neris … 13-Virut), each with a `.pcap` of real traffic and an Argus
`.binetflow` label file. Labels come from the capture authors, not from us.

**Fetched by.** `snort_validation/fetch_stratosphere.sh`
**Lands in.** `data/stratosphere/`

**Why it matters for the experiment.** The previous flow-level features were
derived from Argus `.binetflow` aggregates. With the raw pcaps we can compute
packet-level features (size distribution, inter-arrival timing, TCP flag
mix, payload statistics) that were previously unavailable — and, crucially,
those features are computed from the same bytes Snort actually inspects.

## 2. Ruleset: ET Open, C2 subset

**Source.** `https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz`
(Emerging Threats Open, 47 rule files).

**Builder.** `snort_validation/build_et_open_c2_ruleset.py`
**Output.** `snort_validation/et_open_c2/et_open_c2.rules` + `BUILD_REPORT.json`

### Selection policy

A rule is **included** when all of these hold:

1. It is an `alert` rule. `drop`/`reject` never fire in offline pcap mode.
2. It has at least one `content:` match.
3. Its `msg` marks it as C2 / botnet / backdoor / RAT / beacon activity, or it
   comes from a file that is C2-specific by construction.

### Two exclusions worth naming

**Pure IP blacklists are excluded.** `emerging-botcc.rules`,
`emerging-ciarmy.rules`, `emerging-compromised.rules`, `emerging-dshield.rules`,
and `threatview_CS_c2.rules` are 100% IP/CIDR reputation lists (652 rules).
They match IPs from live abuse.ch feeds. The CTU-13 capture is from 2011 and
uses lab addresses, so **none of them can ever fire**. Including them would
inflate the rule count while contributing zero detections. The count of
excluded blacklist rules is recorded in the build report.

**Orphan flowbits are excluded.** 36 rules gate on `flowbits:isset,X` where no
rule in the shipped subset sets `X`. Snort accepts them silently, but they can
never match. They are dropped and listed in the build report.

### Result

```
alert rules seen:            52,363
skipped (IP blacklist file):    652
skipped (no content match):     957
skipped (not C2-related):    29,344
skipped (orphan flowbit):        36
INCLUDED C2 rules:           21,374
```

Snort 2.9.20 loads the ruleset cleanly: `Snort successfully validated the
configuration!` (~10 s, ~380 MB RSS).

### Config

`snort_validation/et_open_c2/snort_et_c2.conf`

Two details that cost real debugging time, recorded so they are not rediscovered:

- **ET rules require service variables to be defined.** Undefined `$DNS_SERVERS`
  etc. cause a fatal exit, not a warning.
- **`!any` is illegal.** `var DNS_SERVERS any` plus a rule header
  `![$SMTP_SERVERS,$DNS_SERVERS]` produces
  `ERROR: !any is not allowed`. The server variables that appear negated are
  therefore given concrete RFC5737 documentation addresses (`192.0.2.10/11`),
  which captured traffic never uses. This keeps the rule's intent ("not a
  known mail/DNS server") intact instead of silently disabling it.
