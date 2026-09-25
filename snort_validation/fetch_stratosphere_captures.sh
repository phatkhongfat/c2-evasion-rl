#!/usr/bin/env bash
# Fetch Stratosphere IPS / Malware Capture Facility pcaps (MCFP distribution).
#
# Stratosphere IPS (Sebastian Garcia's lab, CTU Prague) publishes the CTU-13
# dataset AND the long-term "CTU-Malware-Capture-Botnet-N" captures through
# mcfp.felk.cvut.cz.  This script fetches one pcap per requested capture into
# data/stratosphere/<capture-dir>/ and never overwrites an existing file.
#
# Usage:
#   bash snort_validation/fetch_stratosphere_captures.sh            # default set
#   bash snort_validation/fetch_stratosphere_captures.sh 47 48 59   # by number
set -uo pipefail

REPO=/root/.hermes/c2-evasion-rl
DEST="$REPO/data/stratosphere/mcfp"
BASE=https://mcfp.felk.cvut.cz/publicDatasets
mkdir -p "$DEST"

# dir:pcap pairs.  Chosen for distinct malware families and modest size.
DEFAULT_PAIRS=(
  "CTU-Malware-Capture-Botnet-47:botnet-capture-20110816-donbot.pcap"       # DonBot
  "CTU-Malware-Capture-Botnet-48:botnet-capture-20110816-sogou.pcap"        # Sogou
  "CTU-Malware-Capture-Botnet-46:botnet-capture-20110815-fast-flux.pcap"    # Virut
  "CTU-Malware-Capture-Botnet-49:botnet-capture-20110816-qvod.pcap"         # Murlo
  "CTU-Malware-Capture-Botnet-59:2014-03-12_capture-win15.pcap"             # unknown
  "CTU-Malware-Capture-Botnet-43:botnet-capture-20110811-neris.pcap"        # Neris
  "CTU-Malware-Capture-Botnet-44:botnet-capture-20110812-rbot.pcap"         # Rbot
  "CTU-Malware-Capture-Botnet-52:botnet-capture-20110818-bot-2.pcap"        # RBot
  "CTU-Malware-Capture-Botnet-53:botnet-capture-20110819-bot.pcap"          # NSIS.ay
  "CTU-Malware-Capture-Botnet-67-1:2014-04-07_capture-win14.pcap"           # Cridex
  "CTU-Malware-Capture-Botnet-90:192.168.3.104-unvirus.pcap"                # Conficker
)

pairs=("${DEFAULT_PAIRS[@]}")
if [ "$#" -gt 0 ]; then
  pairs=()
  for n in "$@"; do
    case "$n" in
      47) pairs+=("CTU-Malware-Capture-Botnet-47:botnet-capture-20110816-donbot.pcap");;
      48) pairs+=("CTU-Malware-Capture-Botnet-48:botnet-capture-20110816-sogou.pcap");;
      46) pairs+=("CTU-Malware-Capture-Botnet-46:botnet-capture-20110815-fast-flux.pcap");;
      49) pairs+=("CTU-Malware-Capture-Botnet-49:botnet-capture-20110816-qvod.pcap");;
      59) pairs+=("CTU-Malware-Capture-Botnet-59:2014-03-12_capture-win15.pcap");;
      43) pairs+=("CTU-Malware-Capture-Botnet-43:botnet-capture-20110811-neris.pcap");;
      44) pairs+=("CTU-Malware-Capture-Botnet-44:botnet-capture-20110812-rbot.pcap");;
      52) pairs+=("CTU-Malware-Capture-Botnet-52:botnet-capture-20110818-bot-2.pcap");;
      53) pairs+=("CTU-Malware-Capture-Botnet-53:botnet-capture-20110819-bot.pcap");;
      55) pairs+=("CTU-Malware-Capture-Botnet-55:capture-win13.pcap");;
      14) pairs+=("CTU-Malware-Capture-Botnet-14:2013-10-18_capture-win15.pcap");;
      11) pairs+=("CTU-Malware-Capture-Botnet-11:capture-win19.pcap");;
      64) pairs+=("CTU-Malware-Capture-Botnet-64:2014-04-07_capture-win6.pcap");;
      22) pairs+=("CTU-Malware-Capture-Botnet-22:2013-11-06_capture-win8.pcap");;
      9) pairs+=("CTU-Malware-Capture-Botnet-9:2013-08-20_captureWin5.pcap");;
      42) pairs+=("CTU-Malware-Capture-Botnet-42:botnet-capture-20110810-neris.pcap");;
      65) pairs+=("CTU-Malware-Capture-Botnet-65:2014-04-07_capture-win11.pcap");;
      67-1) pairs+=("CTU-Malware-Capture-Botnet-67-1:2014-04-07_capture-win14.pcap");;
      90) pairs+=("CTU-Malware-Capture-Botnet-90:192.168.3.104-unvirus.pcap");;
      *) echo "[-] unknown capture number: $n" >&2;;
    esac
  done
fi

fail=0
for pair in "${pairs[@]}"; do
  dir="${pair%%:*}"; pcap="${pair##*:}"
  out="$DEST/$dir/$pcap"
  if [ -s "$out" ]; then
    echo "[=] have $pcap ($(du -h "$out" | cut -f1))"
    continue
  fi
  mkdir -p "$DEST/$dir"
  echo "[*] fetching $pcap ..."
  if curl -L --fail --retry 3 --retry-delay 2 --max-time 900 \
       -o "$out.part" "$BASE/$dir/$pcap"; then
    mv "$out.part" "$out"
    echo "    ok $(du -h "$out" | cut -f1)"
  else
    rm -f "$out.part"
    echo "    FAILED $dir/$pcap" >&2
    fail=$((fail + 1))
  fi
done
echo "[*] pcaps under $DEST: $(find "$DEST" -name '*.pcap' | wc -l), failures: $fail"
exit $((fail > 0))
