#!/usr/bin/env python3
"""Quick smoke test: run Snort validation on a small subset of episodes."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from validate_with_snort import SnortValidator

REPO = Path(__file__).parent.parent
snort_conf = REPO / "snort_validation" / "rules" / "snort.conf"
output_dir = REPO / "snort_validation" / "pcaps"

test_data = json.load(open(REPO / "snort_validation" / "reports" / "test_evaluation.json"))
episodes = test_data["episodes"]
print(f"Testing Snort validation on {len(episodes)} episodes...")

validator = SnortValidator(snort_conf, output_dir)
results = validator.validate_episodes(episodes)
print(f"Detection rate: {results.get('overall_detection_rate', 'N/A')}")
print(json.dumps(results, indent=2, default=str))