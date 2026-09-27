"""Mechanisms A (protocol-aware padding) and B (length-prefixed wrapper).

A is only legal on HTTP: junk headers are skipped by a real server.  A is
NOT the same as a raw prepend -- prepending to a Neris binary record chain or
in front of an HTTP request line breaks both parsers and must be rejected.
"""

import sys
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from endpoint_model import detect_framing, parse_command  # noqa: E402
from hidden_defender_env import (  # noqa: E402
    ACTION_NAMES,
    apply_mech,
    load_corpus,
    mech_applicable,
    payloads_of,
    semantics_intact,
)


def _flow(split, framing):
    for f in load_corpus(split):
        raw = b"".join(payloads_of(f["packets"]))
        if detect_framing(raw) == framing:
            return f
    raise AssertionError(f"no {framing} flow in {split}")


def test_corpus_has_both_framings():
    found = set()
    for split in ("train", "test"):
        for f in load_corpus(split):
            found.add(detect_framing(b"".join(payloads_of(f["packets"]))))
    assert {"http", "neris"} <= found


def test_http_header_pad_keeps_the_command():
    """A: the server skips the junk headers, so the command still arrives."""
    flow = _flow("train", "http")
    original = payloads_of(flow["packets"])
    mutated = apply_mech(flow["packets"], "http_header_pad")
    assert semantics_intact(original, mutated)


def test_http_header_pad_actually_changes_the_wire():
    """Otherwise it is a no-op and proves nothing."""
    flow = _flow("train", "http")
    original = payloads_of(flow["packets"])
    mutated = apply_mech(flow["packets"], "http_header_pad")
    assert payloads_of(mutated) != original


def test_http_header_pad_is_inapplicable_to_neris():
    """HTTP headers are meaningless to a binary record chain, so this must be
    reported as not applicable rather than counted as an evasion or a failure."""
    flow = _flow("train", "neris")
    original = payloads_of(flow["packets"])
    assert mech_applicable(original, "http_header_pad") is False
    mutated = apply_mech(flow["packets"], "http_header_pad")
    assert payloads_of(mutated) == original  # no-op, not a broken channel


def test_both_mechanisms_are_registered():
    assert "http_header_pad" in ACTION_NAMES
    assert "length_wrapper" in ACTION_NAMES


def test_length_wrapper_round_trips():
    """B: the declared offset tells the handler where real data starts."""
    flow = _flow("train", "http")
    original = payloads_of(flow["packets"])
    mutated = apply_mech(flow["packets"], "length_wrapper")
    assert detect_framing(payloads_of(mutated)[0]) == "length2"
    assert parse_command(b"".join(payloads_of(mutated)), "length2") == b"".join(original)


def test_length_wrapper_is_not_readable_by_the_original_handler():
    """The original handler cannot read the wrapped stream, so B is only valid
    for a flow that is already length-framed."""
    flow = _flow("train", "http")
    original = payloads_of(flow["packets"])
    assert mech_applicable(original, "length_wrapper") is False


def test_prepend_still_breaks_the_http_request_line():
    """The old raw prepend must NOT become legal just because A exists."""
    flow = _flow("train", "http")
    original = payloads_of(flow["packets"])
    assert not semantics_intact(original, apply_mech(flow["packets"], "prepend8"))
