"""TDD: --mechs flag on the ceiling sweep.

split_slow is implemented but deliberately NOT in ACTION_NAMES (adding it
would change N_ACTIONS and invalidate the PPO checkpoint). The sweep must
still be able to measure it, so it gets a --mechs override that replaces the
default ACTION_NAMES list without touching the action space.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from ownership_ceiling_sweep import build_parser   # noqa: E402


def test_parser_defaults_to_full_action_names():
    args = build_parser().parse_args([])
    assert args.mechs is None or args.mechs == ""


def test_parser_accepts_a_comma_separated_mech_list():
    args = build_parser().parse_args(["--mechs", "split_slow,noop"])
    assert "split_slow" in args.mechs


def test_resolve_mechs_replaces_default_when_given():
    from ownership_ceiling_sweep import resolve_mechs
    got = resolve_mechs("split_slow,noop")
    assert got == ["split_slow", "noop"]


def test_resolve_mechs_falls_back_to_action_names_when_empty():
    from ownership_ceiling_sweep import resolve_mechs
    from hidden_defender_env import ACTION_NAMES
    assert resolve_mechs(None) == ACTION_NAMES
    assert resolve_mechs("") == ACTION_NAMES