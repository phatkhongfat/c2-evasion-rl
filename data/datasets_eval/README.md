# Botnet Datasets for Baseline Evaluation

Testing multiple datasets to find the best baseline (20-40% evasion) for RL training.

## Datasets

1. **CTU-13** (current) - Botnet captures from CTU University
   - Status: Already loaded (262K flows)
   - Baseline: 93% evasion (too high)

2. **CICIDS2017** - Realistic intrusion detection dataset
   - Source: Canadian Institute for Cybersecurity
   - Contains: DDoS, Brute Force, XSS, SQL Injection, Infiltration, Botnets
   - Download: https://www.unb.ca/cic/datasets/ids-2017.html

3. **UNSW-NB15** - Modern network traffic dataset
   - Source: UNSW Canberra
   - Contains: 9 attack types including botnet, backdoor, exploits
   - Download: https://research.unsw.edu.au/projects/unsw-nb15-dataset

4. **Bot-IoT** - IoT botnet dataset
   - Source: UNSW
   - Contains: DDoS, DoS, OS Scan, Service Scan, Data Theft
   - Download: https://research.unsw.edu.au/projects/bot-iot-dataset

5. **ISCX Botnet 2014** - IRC botnet traffic
   - Source: Canadian Institute for Cybersecurity
   - Contains: IRC, HTTP, P2P botnets
   - Download: https://www.unb.ca/cic/datasets/botnet.html

## Evaluation Plan

For each dataset:
1. Load flows + extract features
2. Test against multiple rulesets:
   - Original 6 rules (Snort behavioral)
   - Aggressive 8 rules (lowered thresholds)
   - ET emerging-botcc rules (IP-based)
   - ML-based classifier (XGBoost/RandomForest)
3. Measure baseline evasion rate
4. Select dataset+ruleset with 20-40% evasion
5. Train packet-level agent on that combination

Target: Find a setup where random policy evades 20-40%, leaving room for RL to improve to 50-70%.
