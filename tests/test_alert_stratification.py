"""P2 classtype stratification tests (plan Task 2.6). RED until alert_strat.py exists."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "snort_validation"))

RULES = """\
alert tcp any any -> any $HTTP_PORTS (msg:"x"; content:"x"; sid:1001; classtype:trojan-activity;)
alert udp any any -> any any (msg:"y"; sid:1002; classtype:policy-violation;)
"""

SWEEP = {
    "rows": [
        {"flow_id": "flow_a", "mech": "split8",
         "evaded": True, "valid_evasion": True,
         "baseline_sids": [1001]},
        {"flow_id": "flow_a", "mech": "split16",
         "evaded": True, "valid_evasion": False,
         "baseline_sids": [1001]},
        {"flow_id": "flow_b", "mech": "split8",
         "evaded": False, "valid_evasion": False,
         "baseline_sids": [1002]},
    ]
}


def test_sid_classtypes_maps_both_sids(tmp_path):
    from alert_strat import sid_classtypes
    p = tmp_path / "c.rules"
    p.write_text(RULES)
    assert sid_classtypes(p) == {1001: "trojan-activity", 1002: "policy-violation"}


def test_stratify_groups_by_classtype(tmp_path):
    from alert_strat import stratify
    rules, sweep = tmp_path / "c.rules", tmp_path / "sweep.json"
    rules.write_text(RULES)
    sweep.write_text(json.dumps(SWEEP))
    res = stratify(sweep, rules)
    # flow_a (trojan-activity) has 2 cells, flow_b (policy-violation) has 1
    assert set(res) == {"trojan-activity", "policy-violation"}
    tro = res["trojan-activity"]
    assert tro["split8"] == {"flows": 1, "evaded": 1, "valid": 1}
    assert tro["split16"] == {"flows": 1, "evaded": 1, "valid": 0}
    pol = res["policy-violation"]
    assert pol["split8"] == {"flows": 1, "evaded": 0, "valid": 0}
    # valid cell lands in the trojan group only
    assert pol["split8"]["valid"] == 0


def test_stratify_counts_flow_once_per_group(tmp_path):
    """A flow with 2 sids of the SAME classtype counts as 1 flow in that group."""
    from alert_strat import stratify
    rules, sweep = tmp_path / "c.rules", tmp_path / "sweep.json"
    rules.write_text(RULES)
    sweep.write_text(json.dumps({"rows": [
        {"flow_id": "flow_a", "mech": "split8",
         "evaded": True, "valid_evasion": True,
         "baseline_sids": [1001, 1002]},
    ]}))
    res = stratify(sweep, rules)
    # flow_a has one sid per group -> appears once in EACH group (2 groups, 1 flow each)
    assert res["trojan-activity"]["split8"]["flows"] == 1
    assert res["policy-violation"]["split8"]["flows"] == 1
