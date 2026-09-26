# Dataset sources

The capture pcaps are **not in git** and never should be: the largest ones are
hundreds of MB to several GB, GitHub rejects any single file over 100 MB, this
repository is public, and the CTU-13 / Malware Capture Facility releases carry
an academic-use licence that forbids redistribution. `data/stratosphere/` is
gitignored for exactly that reason.

What follows is the manifest those pcaps are fetched from. Every URL and size in
the tables was verified with a live `curl -I` against the MCFP host; the sizes
are `content-length` at the time of writing, not estimates.

Base host: <https://mcfp.felk.cvut.cz/publicDatasets>

## The two captures used for the packet-level results

These are the captures every number on branch `packet-level-rl` is measured on.

| Capture | Directory | Size | Local path after fetch |
|---|---|---|---|
| `botnet-capture-20110811-neris.pcap` | `CTU-Malware-Capture-Botnet-43` | 34 MB | `data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-43/` |
| `botnet-capture-20110819-bot.pcap` | `CTU-Malware-Capture-Botnet-53` | 281 MB | `data/stratosphere/CTU-13-Dataset/12/` |

`20110811-neris` is the capture the policy is trained and evaluated on.
`20110819-bot` is the held-out capture it currently loses to (see
`snort_validation/reports/feasibility/feat15.txt`).

## Fetching

```bash
# CTU-13, the full dataset tarball (~1.9 GB) -- contains 20110819-bot
bash snort_validation/fetch_stratosphere.sh

# Individual MCFP captures, no tarball (~5.7 GB for the full default list)
bash snort_validation/fetch_stratosphere_captures.sh 43   # just 20110811-neris
bash snort_validation/fetch_stratosphere_captures.sh 43 53
```

Passing directory numbers fetches only those captures. With no arguments the
script takes its whole `DEFAULT_PAIRS` list, which is **~5.7 GB** — see the size
column below before running it bare.

## Full manifest

| Directory | Capture | Size | Family / note |
|---|---|---|---|
| `CTU-13-Dataset` | `CTU-13-Dataset.tar.bz2` | 1905 MB | whole dataset |
| `CTU-Malware-Capture-Botnet-43` | `botnet-capture-20110811-neris.pcap` | 34 MB | Neris — main training capture |
| `CTU-Malware-Capture-Botnet-53` | `botnet-capture-20110819-bot.pcap` | 281 MB | NSIS.ay — held-out capture |
| `CTU-Malware-Capture-Botnet-44` | `botnet-capture-20110812-rbot.pcap` | 122 MB | Rbot |
| `CTU-Malware-Capture-Botnet-47` | `botnet-capture-20110816-donbot.pcap` | 5 MB | DonBot |
| `CTU-Malware-Capture-Botnet-48` | `botnet-capture-20110816-sogou.pcap` | 17 MB | Sogou |
| `CTU-Malware-Capture-Botnet-46` | `botnet-capture-20110815-fast-flux.pcap` | 29 MB | Virut |
| `CTU-Malware-Capture-Botnet-49` | `botnet-capture-20110816-qvod.pcap` | 20 MB | Murlo |
| `CTU-Malware-Capture-Botnet-59` | `2014-03-12_capture-win15.pcap` | 39 MB | unknown |
| `CTU-Malware-Capture-Botnet-90` | `192.168.3.104-unvirus.pcap` | 12 MB | Conficker |
| `CTU-Malware-Capture-Botnet-67-1` | `2014-04-07_capture-win14.pcap` | 661 MB | Cridex |
| `CTU-Malware-Capture-Botnet-52` | `botnet-capture-20110818-bot-2.pcap` | **4066 MB** | RBot |

> **The last two rows are the reason to always pass a directory number.**
> `botnet-capture-20110818-bot-2.pcap` alone is just over 4 GB. A bare
> `fetch_stratosphere_captures.sh` downloads the whole default list, ~5.7 GB,
> and that one file is most of it. The cross-capture work in this repo only
> needs 43 and 53.

## Licensing

These captures are published by the Malware Capture Facility Project (Stratosphere
IPS, Czech Technical University) for academic research use. Cite MCFP/Stratosphere
when using them; do not redistribute the pcaps themselves. Fetching them from the
official host under the stated licence is the supported path — vendoring them into
a public git repository is not.
