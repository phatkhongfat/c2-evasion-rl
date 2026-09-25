#!/usr/bin/env bash
# Fetch Stratosphere IPS / CTU-13 raw pcaps from the official MCFP host.
# Stratosphere IPS (Sebastian Garcia's lab) is the publisher of CTU-13;
# mcfp.felk.cvut.cz is their official distribution mirror.
set -euo pipefail

DEST=/root/.hermes/c2-evasion-rl/data/stratosphere
mkdir -p "$DEST"
cd "$DEST"

URL=https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2

if [ ! -f CTU-13-Dataset.tar.bz2 ]; then
  echo "[*] Downloading $URL"
  curl -L --fail --retry 3 -C - -o CTU-13-Dataset.tar.bz2 "$URL"
fi
echo "[*] Archive size: $(du -h CTU-13-Dataset.tar.bz2 | cut -f1)"

echo "[*] Archive contents (sample):"
tar tjf CTU-13-Dataset.tar.bz2 | head -30

echo "[*] Extracting..."
tar xjf CTU-13-Dataset.tar.bz2

echo "[*] Extracted pcap inventory:"
find . -name '*.pcap' -printf '%s\t%p\n' | sort -rn | head -20
echo "[*] Total pcaps: $(find . -name '*.pcap' | wc -l)"
echo "[*] Disk used: $(du -sh . | cut -f1)"
echo "[*] Done."
