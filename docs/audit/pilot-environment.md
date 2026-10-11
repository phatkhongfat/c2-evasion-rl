# Environment diagnosis — actual execution
Runtime: /root/.hermes/c2-evasion-rl/.venv/bin/python; Python 3.11.16.
Installed metadata: stable-baselines3 2.9.0; sb3-contrib 2.2.1; gymnasium 1.3.0; torch 2.14.0+cpu; scapy 2.7.0; pytest 9.1.1.
Bare .venv/bin/pip shebang: /root/.hermes/c2-evasion-rl/.venv/bin/python3.12.
Correct-interpreter installer tested: `.venv/bin/python -m pip --version` -> pip 24.0 in .venv/lib/python3.11/site-packages/pip (python 3.11).
Dependency health command: `.venv/bin/python -m pip check` -> No broken requirements found. Exit 0.

## Important correction
Installed sb3-contrib 2.2.1 declares `stable-baselines3 <3.0,>=2.2.1`; installed 2.9.0 meets this metadata constraint. Therefore mixed versions are NOT a demonstrated dependency incompatibility. pip check does not prove API/checkpoint compatibility or clean-install reproducibility. The mismatch with environment.yml 2.9.0 remains real.
Stable-baselines3 metadata includes gymnasium<2.0,>=0.29.1 and torch<3.0,>=2.8; installed versions satisfy these as checked by pip.

## Proposed next environment action
Do not patch pip shebang or upgrade live packages. For read-only diagnosis/use of existing environment, explicitly use `.venv/bin/python -m pip`, not `.venv/bin/pip`.
Before installation: create an approved separate Python 3.11 environment and choose whether reproducing current observed versions or intended declared versions. Preserve original venv. Resolve dependencies in the separate environment; verify benign imports/tests and checkpoint compatibility independently before migration. No package access or install was attempted in this pilot.
Gate B PASS for diagnosis; clean install and runtime model compatibility remain UNKNOWN.
