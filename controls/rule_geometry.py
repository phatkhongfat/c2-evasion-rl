"""Rule geometry: why fragmentation is one equivalence class on corpus v3fixed.

Reads the real ET Open C2 ruleset that the eval pipeline actually uses and
reports, per SID, how long the longest contiguous `content` pattern is.

That single number is what decides whether two fragmentation units can be
distinguished on a flow:

  * a content of length L can survive a fragmentation unit U only if it happens
    to fall entirely inside one unit (L <= U) AND its offset happens to align;
  * once L > U the content is guaranteed to be cut, so the rule cannot fire;
  * a bigger U is never *less* destructive than a smaller one.

So when every alerting rule is broken by the SMALLEST available unit, every
fragmentation mechanism is equivalent in effect and the oracle collapses onto a
whole equivalence class instead of a single action.

Read-only: no Snort, no training, no report mutation.
"""

from __future__ import annotations

import re
from pathlib import Path

# The five alerting SID families in corpus v3fixed (train + test, 62 flows).
CORPUS_SIDS = ("2016413", "2014169", "2012533", "2014635", "2017287")

# Smallest fragmentation unit in the RL action space (split8 / split8_16 / ...).
MIN_FRAGMENTATION_UNIT = 8

_CONTENT_RE = re.compile(r'content:"((?:[^"\\]|\\.)*)"')
_HEX_RE = re.compile(r"[^0-9a-fA-F ]")


def parse_alert_rule(ruleset: Path, sid: str) -> str:
    """Return the single alert line carrying `sid`, or "" if absent."""
    if not ruleset.exists():
        return ""
    for line in ruleset.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("alert") and f"sid:{sid};" in line:
            return line
    return ""


def _hex_segment_len(segment: str) -> int:
    return len(_HEX_RE.sub("", segment).replace(" ", "")) // 2


def content_lengths(rule_line: str) -> list[int]:
    """Byte length of every `content:` pattern, in order.

    A pattern may mix hex and literal segments, e.g. `|02|su|00|` is one ASCII
    byte, the two characters `su`, then one more byte -- 4 bytes total. Measured
    naively as hex digits only it would collapse to 2 and understate every rule
    that anchors on a printable needle.
    """
    out = []
    for raw in _CONTENT_RE.findall(rule_line or ""):
        total = 0
        # Splitting on "|" puts every pipe-delimited segment at an ODD index and
        # every literal run at an EVEN index. Only the odd ones are byte-encoded:
        # in `d1|3a|ad2|3a|id20|3a|` the `3a`s are hex bytes while the bare `d1`,
        # `ad2` and `id20` are literal ASCII that merely happen to be hex-shaped.
        for index, segment in enumerate(raw.split("|")):
            if segment == "":
                continue
            if index % 2 == 1:
                stripped = _HEX_RE.sub("", segment).replace(" ", "")
                total += (
                    len(stripped) // 2
                    if stripped and len(stripped) % 2 == 0
                    else len(segment.encode())
                )
            else:
                total += len(segment.encode())
        out.append(total)
    return out


def longest_content(ruleset: Path, sid: str) -> int:
    lengths = content_lengths(parse_alert_rule(ruleset, sid))
    return max(lengths) if lengths else 0


def rule_geometry(ruleset: Path, sid: str) -> dict:
    lengths = content_lengths(parse_alert_rule(ruleset, sid))
    return {
        "sid": sid,
        "n_content": len(lengths),
        "content_lengths": lengths,
        "longest": max(lengths) if lengths else 0,
    }


def discriminating_sids(
    ruleset: Path, low: int = 16, high: int = 24, limit: int | None = None
) -> list[str]:
    """SIDs whose longest content sits in [low, high).

    A flow alerting under such a rule is the case where `split8` (or any U
    below `low`) destroys the pattern while a larger unit may not -- which is
    exactly the structure that makes per-flow mechanism selection possible.
    Such a SID is what corpus v3fixed is missing.
    """
    found = []
    for line in ruleset.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("alert"):
            continue
        m = re.search(r"sid:(\d+);", line)
        if not m:
            continue
        lengths = content_lengths(line)
        if lengths and low <= max(lengths) < high:
            found.append(m.group(1))
            if limit is not None and len(found) >= limit:
                break
    return found


def default_ruleset() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "snort_validation/et_open_c2/et_open_c2.rules"
    )


def _main() -> None:  # pragma: no cover - CLI helper
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ruleset", type=Path, default=default_ruleset())
    args = ap.parse_args()

    print(f"MIN_FRAGMENTATION_UNIT = {MIN_FRAGMENTATION_UNIT}")
    for sid in CORPUS_SIDS:
        print(json.dumps(rule_geometry(args.ruleset, sid)))
    for low, high in ((16, 24), (24, 32), (32, 10**6)):
        n = len(discriminating_sids(args.ruleset, low, high))
        hi = "inf" if high >= 10**6 else str(high)
        print(f"rules with {low} <= longest < {hi}: {n}")


if __name__ == "__main__":  # pragma: no cover
    _main()