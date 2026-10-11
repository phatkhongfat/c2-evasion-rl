import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
_MAIN = (REPO / "ai_agent" / "eval_fixed_pipeline.py").read_text().split(
    "def main")[1]


def test_eval_accepts_capture():
    assert '"--capture"' in _MAIN
    assert "capture=args.capture" in _MAIN


def test_eval_accepts_corpus():
    """P3: the eval CLI must accept a corpus override (default None = v1)."""
    assert '"--corpus"' in _MAIN
    assert "corpus=args.corpus" in _MAIN
