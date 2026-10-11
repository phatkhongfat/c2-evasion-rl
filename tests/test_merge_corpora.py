import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controls"))
from merge_corpora import corrected_framing


def test_dns_udp_is_not_http():
    assert corrected_framing({"key": ("1.1.1.1", 5, "8.8.8.8", 53, "udp"), "framing": "http"}) == "dns"


def test_tcp_http_kept():
    assert corrected_framing({"key": ("1.1.1.1", 5, "8.8.8.8", 80, "tcp"), "framing": "http"}) == "http"


def test_nonstandard_udp_port_keeps_label():
    assert corrected_framing({"key": ("1.1.1.1", 5, "8.8.8.8", 411, "udp"), "framing": "neris"}) == "neris"