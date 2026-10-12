"""T3 (P12): ``score_flow_real`` must report BOTH semantics bars side by side.

The byte bar (``semantics_ok`` / ``valid_evasion``) is UNCHANGED so old reports
stay comparable; the endpoint bar (``endpoint_ok`` /
``valid_evasion_endpoint``) is ADDITIONAL.  These tests pin that both verdicts
are present and INDEPENDENTLY derived -- a mutation can pass one and fail the
other, which is the entire reason the second bar exists.

No Snort is executed here: ``eval_pipeline._run_snort`` is monkeypatched, so
this exercises the verdict wiring only.  Letting a pure-logic test depend on a
600 s external engine would make it untrustworthy and slow.

Note on fixtures: the plan pointed at ``tests/test_eval_cli.py`` for a flow
helper, but that file only does source-string assertions and has no packet
fixture.  The established packet fixture for this bar is in
``tests/test_endpoint_command_bar.py``; the minimal one below follows it.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for sub in ("snort_validation", "ai_agent"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from scapy.all import Ether, IP, Raw, TCP  # noqa: E402

CIP, SIP = "10.0.0.1", "10.0.0.9"
HTTP = (b"POST /getjson HTTP/1.1\r\nAccept: */*\r\nHost: a.com\r\n"
        b"Content-Length: 4\r\n\r\ndata=1")


def _one_flow_packets():
    return [Ether() / IP(src=CIP, dst=SIP)
            / TCP(sport=1234, dport=80, seq=1000, flags="PA") / Raw(HTTP)]


def _client_ip():
    return CIP


@pytest.fixture
def no_snort(monkeypatch):
    """Stub the Snort call: report 'no alerts' without invoking the engine."""
    import eval_pipeline
    monkeypatch.setattr(eval_pipeline, "_run_snort", lambda *a, **k: (0, []))
    return eval_pipeline


def test_score_flow_real_reports_both_bars(no_snort):
    """Both verdicts must be present and independently derived."""
    out = no_snort.score_flow_real(_one_flow_packets(), _client_ip(),
                                   attempt_id=0, mech="http_header_pad")
    assert set(["semantics_ok", "valid_evasion",
                "endpoint_ok", "valid_evasion_endpoint"]) <= set(out)


def test_both_bars_are_independently_derived(no_snort):
    """http_header_pad changes the WIRE but not the COMMAND.

    The byte bar must reject it; the endpoint bar must certify it.  If the two
    ever collapse to the same value the second bar bought nothing.
    """
    out = no_snort.score_flow_real(_one_flow_packets(), _client_ip(),
                                   attempt_id=0, mech="http_header_pad")
    assert out["semantics_ok"] is False
    assert out["endpoint_ok"] is True
    assert out["evaded"] is True                 # stubbed Snort: no alerts
    assert out["valid_evasion"] is False
    assert out["valid_evasion_endpoint"] is True


def test_endpoint_bar_still_requires_evasion(monkeypatch):
    """A preserved command on an ALERTED flow is not a valid endpoint evasion."""
    import eval_pipeline
    monkeypatch.setattr(eval_pipeline, "_run_snort", lambda *a, **k: (1, [2012627]))
    out = eval_pipeline.score_flow_real(_one_flow_packets(), _client_ip(),
                                        attempt_id=0, mech="http_header_pad")
    assert out["endpoint_ok"] is True
    assert out["evaded"] is False
    assert out["valid_evasion_endpoint"] is False


def test_byte_bar_verdicts_are_unchanged(no_snort):
    """The new keys must not perturb the existing ones (old reports comparable)."""
    out = no_snort.score_flow_real(_one_flow_packets(), _client_ip(),
                                   attempt_id=0, mech="split8")
    assert out["semantics_ok"] is True
    assert out["valid_evasion"] is True
    assert out["endpoint_ok"] is True
