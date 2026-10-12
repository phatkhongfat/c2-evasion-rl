"""TDD: --ownership flag on the ceiling sweep.

The sweep hardcoded ownership='both'; the client-only ceiling (the conservative
threat model) is a different measurement and must be selectable.  Default stays
'both' so existing reports reproduce bit-identically.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))


def test_parser_defaults_to_both():
    from ownership_ceiling_sweep import build_parser
    assert build_parser().parse_args([]).ownership == "both"


def test_parser_accepts_client():
    from ownership_ceiling_sweep import build_parser
    args = build_parser().parse_args(["--ownership", "client"])
    assert args.ownership == "client"


def test_parser_rejects_unknown_ownership():
    from ownership_ceiling_sweep import build_parser
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--ownership", "server"])
