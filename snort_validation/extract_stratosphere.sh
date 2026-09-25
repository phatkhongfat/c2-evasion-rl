#!/usr/bin/env bash
# Extract only the traffic captures and their labels from the CTU-13 archive.
# The archive also ships malware binaries (.exe) which are not needed and are
# deliberately not extracted.
set -euo pipefail

DEST=/root/.hermes/c2-evasion-rl/data/stratosphere
cd "$DEST"

echo "[*] Extracting .pcap and .binetflow only..."
tar xjf CTU-13-Dataset.tar.bz2 \
  --wildcards \
  'CTU-13-Dataset/*/*.pcap' \
  'CTU-13-Dataset/*/*.binetflow' \
  'CTU-13-Dataset/*/README*'

echo "[*] Extracted pcap inventory:"
find CTU-13-Dataset -name '*.pcap' -printf '%s\t%p\n' | sort -rn
echo "[*] Total pcaps: $(find CTU-13-Dataset -name '*.pcap' | wc -l)"
echo "[*] Total binetflow: $(find CTU-13-Dataset -name '*.binetflow' | wc -l)"
echo "[*] Size: $(du -sh CTU-13-Dataset | cut -f1)"
echo "[*] Done."
