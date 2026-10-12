"""TDD (P6): winner-signature stratification."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))

from winner_signature import signature_of, divergent_flows, stratified_split  # noqa: E402


def test_signature_of_collects_winning_mechs():
    cells = [{"flow_id": "f1", "mech": "split8", "valid_evasion": True},
             {"flow_id": "f1", "mech": "split_slow", "valid_evasion": False},
             {"flow_id": "f2", "mech": "split8", "valid_evasion": False},
             {"flow_id": "f2", "mech": "split_slow", "valid_evasion": True}]
    sig = signature_of(cells)
    assert sig["f1"] == {"split8"} and sig["f2"] == {"split_slow"}


def test_divergent_flows_needs_two_signatures():
    sig = {"f1": {"split8"}, "f2": {"split_slow"}, "f3": {"split8", "split_slow"}}
    div = divergent_flows(sig)
    assert div["n_classes"] >= 2
    # f3 (won by everything = the intersection) carries no discrimination
    assert "f3" not in div["flows"]
    assert set(div["flows"]) == {"f1", "f2"}


def test_divergent_flows_empty_when_one_signature():
    sig = {"f1": {"split8"}, "f2": {"split8"}}
    div = divergent_flows(sig)
    assert div["flows"] == [] and div["n_classes"] == 0


def test_stratified_split_balances_signatures():
    sig = {f"a{i}": {"split8"} for i in range(10)}
    sig.update({f"b{i}": {"split_slow"} for i in range(10)})
    tr, te = stratified_split(sig, test_ratio=0.25, seed=42)
    classes_te = {frozenset(sig[f]) for f in te}
    assert {"split8"} in classes_te and {"split_slow"} in classes_te
    assert len(te) == 6          # ceil(0.25*10)=3 per class
    assert len(tr) == 14
    # deterministic under seed
    assert stratified_split(sig, 0.25, 42) == (tr, te)
