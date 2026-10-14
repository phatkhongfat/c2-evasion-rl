import sys
from pathlib import Path
sys.path[:0] = ["snort_validation", "ai_agent", "controls"]
from build_corpus_v3 import parse_alerts, extract
from scapy.all import Raw

PRIV = {2019486, 2019471}
alert = parse_alerts(Path("/tmp/cov/botnet-capture-20110812-rbot/alert"))
priv = {k: v for k, v in alert.items() if v.intersection(PRIV)}
print("rbot flows w/ PRIVMSG sids:", len(priv))
found, first = extract(
    Path("data/stratosphere/mcfp/CTU-Malware-Capture-Botnet-44/botnet-capture-20110812-rbot.pcap"),
    priv, 60)
print("extracted:", len(found))
for k in sorted(found)[:4]:
    pk = found[k]
    pay = b"".join(bytes(p[Raw].load) for p in pk if Raw in p)
    print(f"{k} npkts={len(pk)} paylen={len(pay)} head={pay[:90]!r}")
