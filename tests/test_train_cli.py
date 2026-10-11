"""The train CLI must not hardcode the model path or the split.

Hardcoding means every retrain overwrites models/ppo_hidden_defender.zip, i.e.
the previous condition becomes unreproducible the moment the next run starts.
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
_MAIN = (REPO / "ai_agent" / "train_hidden_defender_ppo.py").read_text().split(
    "def main")[1]


def test_model_out_is_configurable():
    assert '"--model-out"' in _MAIN
    assert 'model.save(models_dir / "ppo_hidden_defender")' not in _MAIN


def test_split_is_configurable():
    assert '"--split"' in _MAIN
    assert 'BatchEnv(split="train"' not in _MAIN


def test_capture_is_configurable():
    assert '"--capture"' in _MAIN


def test_corpus_is_configurable():
    """P3: the train CLI must accept a corpus override so the v3fixed corpus
    can be trained on without editing CORPUS_PKL; default None = v1 path."""
    assert '"--corpus"' in _MAIN
    assert "corpus=args.corpus" in _MAIN
