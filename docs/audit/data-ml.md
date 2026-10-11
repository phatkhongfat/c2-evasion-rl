# Data / ML audit
## Confirmed, independently checked
- train_hidden_defender_ppo.py:39–40 explicitly wraps one-step decisions; :159–161 sets gamma=0. hidden_defender_env.py:521–565 advances to next flow. Formulation is contextual-bandit-like selection, not demonstrated sequential control of one connection. A bandit is a special case of an MDP; saying “not mathematically an MDP” would be too strong.
- hidden_defender_corpus.json recomputed: train 1153, test 40, ID intersection zero. Both capture names occur in train AND test. This is not capture-disjoint evaluation; host/capture correlation is not automatically proof of direct label leakage.
- Three existing ppo_both_test_RS64_v2_s{7,42,1337}.json reports all contain actions_chosen={split8:40}. These historical results do not isolate a learned-policy advantage over a fixed baseline, and do not validate the current v3 corpus.
- corpus_config.py:24–34 shuffles the supplied list and takes the first 40. Exact shipped split regeneration needs builder/input-order provenance and an identity test, not only cardinality.
## Additional reviewer findings requiring targeted reproduction
Reviewer reported split regeneration mismatch and checkpoint dimensions [11]/14 across stored models. These are not runtime load compatibility proofs. No model load or training performed by parent. No strong claim that no v3 model exists based only on filenames.
Archived random/greedy/oracle baselines use different split/scorer scopes; compare paired configurations before claiming PPO superiority. Surrogate agreement on a limited corpus cannot certify unseen protocols.
## Historical results not valid as current ceilings
Old v3 7/40 results predate DNS payload handling changes and must not be interpreted as an intrinsic expert ceiling. No new ceiling, packet mutation or evasion optimization was run in this audit.
