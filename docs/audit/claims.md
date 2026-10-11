# Claims audit
README.md:5–10 describes working C2 and headline 40/40. Existing reports support historical harness verdict counts, not independent endpoint completion or general Snort robustness claims.
README.md:56–57 describes replica training 127/128, 896 queries, 7 epochs. Current ppo_hidden_defender.json instead says scorer real_snort, n_flows 64, queries 1472, epochs 23, evasion_pct 90.6, evaded 638. These are different experiments; do not silently replace assertions to make verification green. Preserve run-scoped reports and clarify cumulative vs final metrics.
environment.yml:5 references setup_check.py; direct existence check False.
environment.yml:49 pins sb3-contrib 2.9.0; live Python reports 2.2.1. .venv/bin/pip shebang targets python3.12 while execution Python is 3.11.16. Confirmed interpreter/install mismatch, not proof of runtime incompatibility.
Reviewer found old 16/16 documentation linked alongside 40/40 headlines, conda install vs .venv run inconsistency, and hardcoded paths. Treat as documentation remediation; do not merge results across generations to make numbers agree.
Source data licensing statements remain unverified; do not repeat them as legal conclusions.
