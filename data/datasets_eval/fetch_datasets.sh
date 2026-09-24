#!/bin/bash
# Fetch botnet datasets for baseline evaluation

set -e

echo "[1/5] CICIDS2017 - checking availability..."
# CICIDS2017 requires registration, manual download
echo "  -> Requires registration at https://www.unb.ca/cic/datasets/ids-2017.html"
echo "  -> Skip for now, check Kaggle mirror"

echo "[2/5] Checking Kaggle CICIDS2017..."
if command -v kaggle &>/dev/null; then
    kaggle datasets download -d cicdataset/cicids2017 -p cicids2017/ --unzip 2>/dev/null && echo "  -> Downloaded" || echo "  -> Requires Kaggle API key"
else
    echo "  -> kaggle CLI not installed"
fi

echo "[3/5] UNSW-NB15 - fetching CSV..."
mkdir -p unsw-nb15
curl -sL "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15%20-%20CSV%20Files&files=UNSW-NB15_1.csv" -o unsw-nb15/UNSW-NB15_1.csv 2>&1 | tail -3 || echo "  -> Download failed (link may be expired)"

echo "[4/5] Bot-IoT - checking..."
echo "  -> Requires form submission at https://research.unsw.edu.au/projects/bot-iot-dataset"

echo "[5/5] Checking local Kaggle cache..."
ls -lh ~/.kaggle/datasets/ 2>/dev/null | head -10 || echo "  -> No Kaggle cache"

echo ""
echo "Summary: Most datasets require registration or Kaggle API."
echo "Alternative: Use Kaggle notebooks to access datasets directly."
