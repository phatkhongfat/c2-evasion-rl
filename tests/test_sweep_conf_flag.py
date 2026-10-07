"""Plan Task 3.3: sweep must accept --conf (RED until build_parser is extracted)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))

from ownership_ceiling_sweep import build_parser  # noqa: E402


def test_conf_flag_parses():
    args = build_parser().parse_args(
        ["--split", "test", "--conf", "/x/y.conf"])
    assert args.conf == "/x/y.conf"
    assert args.split == "test"


def test_conf_defaults_to_none():
    assert build_parser().parse_args([]).conf is None
