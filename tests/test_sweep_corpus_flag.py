import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "controls"))
from ownership_ceiling_sweep import build_parser


def test_corpus_flag_defaults_to_none():
    assert build_parser().parse_args([]).corpus is None


def test_corpus_flag_is_accepted():
    assert build_parser().parse_args(["--corpus", "/tmp/x.pkl"]).corpus == "/tmp/x.pkl"