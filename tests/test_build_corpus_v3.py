import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))
from build_corpus_v3 import norm, parse_alerts

LINE = ("08/12-19:55:14.422987  [**] [1:2019486:1] ET TROJAN Possible IRC Bot [**] "
        "[Classification: A Network Trojan was detected] [Priority: 1] "
        "{TCP} 147.32.84.165:1181 -> 78.40.125.4:6667\n")
NAIVE_LINE = LINE.replace("2019486", "2012627")


def test_norm_is_direction_free():
    assert norm("tcp", "1.1.1.1", 5, "2.2.2.2", 80) == norm("tcp", "2.2.2.2", 80, "1.1.1.1", 5)


def test_parse_alerts_keeps_only_non_naive(tmp_path):
    f = tmp_path / "alert"
    f.write_text(LINE + NAIVE_LINE)
    got = parse_alerts(f)
    assert list(got.values()) == [{2019486}]
