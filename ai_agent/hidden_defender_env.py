#!/usr/bin/env python3
"""Gym env for the hidden-defender problem.

One episode = one flow = one query.  The agent sees 8 black-box statistical
features plus a framing/affordance block (OBS_DIM=11) and picks one evasion
mechanism; it never sees the ruleset.  Reward is
+10 for a valid evasion (no alert AND semantics preserved), -10 for breaking the
C2 command while dodging the alert, and -1 for still alerting.

Scoring uses RealRulesReplica by default (0.33 ms/flow, measured 8/8 agreement
with the real Snort binary).  Pass `real_snort=True` to score with the actual
binary instead (1340 ms/flow) -- used by the final verification, not by training.

The action space keeps only mechanisms that were MEASURED to be either valid
evaders or useful negatives, plus the structural Rbot finding (split cannot
break a pattern whose length equals the fragment unit, so prepend must be in
the space for the agent to have any chance on that family).
"""
from __future__ import annotations

import pickle
import re
import sys
from pathlib import Path

import gymnasium as gym
import numpy as np
from gymnasium import spaces
from scapy.all import IP, Raw, TCP, UDP

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from real_packet_env import payload_indices  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

# The ONE semantics bar (Fix 3), shared with the honest evaluation.  Module-level
# import is safe: eval_pipeline imports hidden_defender_env only INSIDE
# functions (deferred), and c2_semantics imports neither, so there is no cycle.
from c2_semantics import (  # noqa: E402
    as_raw,
    bytes_equal_semantics,
    client_ip_of,
    client_ip_of_packets,
    ensure_chain,
    reassembled_client_bytes,
    server_ip_of,
)
from fragment_ops import has_payload, transport_payload  # noqa: E402

CORPUS_PKL = REPO / "snort_validation/reports/hidden_defender_corpus.pkl"

# Mechanism A filler: unknown headers a real server ignores, but a `depth:`
# signature anchored in the HTTP head will still see shifted bytes.
_JUNK_HEADERS = b"".join(
    b"X-Pad-%04d: %s\r\n" % (i, b"A" * 24) for i in range(4)
)

# Mechanism B: declared byte offset of the real data inside the wrapper.
_WRAP_OFFSET = 64

# http_header_case: the field-name token of a header line (RFC 7230 s3.2
# token grammar).  Matched at the start of each header line only.
_HEADER_NAME_RE = re.compile(rb"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):")


def _lower_field_names(head: bytes) -> bytes:
    """Lower-case the field NAME of every header line; leave values alone."""
    lines = head.split(b"\r\n")
    out = [lines[0]]
    for line in lines[1:]:
        m = _HEADER_NAME_RE.match(line)
        out.append(line if m is None else m.group(1).lower() + b":" + line[m.end():])
    return b"\r\n".join(out)

# 15 mechanisms.  split8/16/24 and prepend4/8/12 measured; pad/reorder/ttl
# measured as 0/80 evaders (kept as informative negatives); corrupt8 breaks
# semantics (kept so the -10 penalty is observable); noop is the null action.
# http_header_pad / length_wrapper are protocol-aware (A and B): they are
# applicable only to a flow whose framing can carry them, and
# `mech_applicable` keeps the rest out of the denominator.
# split_slow (index 14) is byte-safe slow fragmentation (fragments spread past
# frag3's 60s timeout); it was measured 40/40 on the v3 test split
# (ceiling_v3_splitslow_fixed.json) and is masked out unless an owned packet
# has transport payload > 8 bytes.
ACTION_NAMES = [
    "split8", "split16", "split24",
    "prepend4", "prepend8", "prepend12",
    "pad16", "reorder", "ttl",
    "corrupt8", "overlap8", "noop",
    "http_header_pad", "length_wrapper",
    "split_slow",
    # P15 (D9/D10, docs/action_space_policy_p15.md): the two P14 mechanisms are
    # promoted to actions.  Appended at the END so every pre-existing index is
    # unchanged; old Discrete(15) checkpoints will not load, which is accepted
    # (retraining is the goal).  Both are HTTP-only and carry measured wire cost.
    "http_header_case", "query_param_prepend",
]
N_ACTIONS = len(ACTION_NAMES)

OBS_DIM = 11

REWARD_EVADE = 10.0
REWARD_BREAK_SEMANTICS = -10.0
REWARD_ALERTED = -1.0

# Action cost penalty (Direction 1): differentiate mechanisms by resource cost.
# In real networks, fragmentation consumes bandwidth/CPU and raises suspicion;
# HTTP header padding is stealthy (legitimate traffic has custom headers).
# RL should learn: "Split only when necessary; prefer padding on HTTP flows."
ACTION_COSTS = {
    0: 0.60,     # split8 (highest cost — many fragments, bandwidth)
    1: 0.50,     # split16
    2: 0.40,     # split24 (lowest split cost)
    3: 0.2,      # prepend4
    4: 0.2,      # prepend8
    5: 0.2,      # prepend12
    6: 0.1,      # pad16 (append junk, low cost)
    7: 0.35,     # reorder (out-of-order penalty, risky)
    8: 0.1,      # ttl (low cost, but unreliable)
    9: 0.4,      # corrupt8 (high risk, breaks semantics anyway)
    10: 0.35,    # overlap8 (ambiguity cost, risky)
    11: 0.0,     # noop (no cost)
    12: 0.05,    # http_header_pad (cheap, natural — legitimate HTTP has custom headers)
    13: 0.25,    # length_wrapper (medium cost — needs protocol awareness)
    # split_slow is the most expensive primitive: it holds a fragment back past
    # frag3's 60s timeout, so the flow stays open ~75s per fragment (a real
    # latency/disruption cost).  Priced ABOVE split8's 0.60 so the agent only
    # pays it when the cheap fast splits do not clear the flow.
    14: 0.65,    # split_slow
    # P15 (D10): both P14 mechanisms change the wire on purpose but add almost
    # no bytes -- http_header_case 0 B (field-name case-fold), query_param_prepend
    # +4..8 B / flow and 0 fragments.  Priced in the http_header_pad band (0.05)
    # and below every split, anchored to the measured wire cost in
    # docs/p14_results.md / docs/p14_cost_headroom.md.
    15: 0.05,    # http_header_case (0 wire bytes)
    16: 0.05,    # query_param_prepend (+4..8 bytes, no fragments)
}


# Shaping bonus for picking the primitive that matches the flow's framing.
PROTOCOL_MATCH_BONUS = 0.15

# Which mechanisms are the *appropriate* primitive for a framing.  The bonus
# below rewards any of these (gated on a real valid evasion) instead of one
# hard-coded action, so the policy is free to prefer whichever is cheapest on
# a given flow while still not collapsing onto the framing-agnostic generic.
#
# ``dns`` and ``irc`` are framings the rebuilt v3 corpus stores; split_slow was
# measured to clear 40/40 v3 test flows, so it is an appropriate primitive
# there.  (Note: the retrained policies converged on split8/split16 instead --
# the fast splits also clear all 40 -- so this is an offered option, not a
# claim that the fast splits fail.)  ``http``/``neris`` keep their sets.
PROTOCOL_APPROPRIATE = {
    "http": ("http_header_pad", "length_wrapper", "split8", "split16", "split24",
             # P15 (D10): the two P14 HTTP-native mechanisms are appropriate here.
             "http_header_case", "query_param_prepend"),
    "neris": ("split8", "split16", "split24", "pad16", "reorder", "ttl"),
    "dns": ("split_slow",),
    "irc": ("split_slow",),
}


def payloads_of(pkts):
    return [bytes(p[Raw].load) for p in pkts if Raw in p]


def framing_of(payloads) -> str:
    """Protocol framing of the flow's command stream, from its first bytes."""
    from endpoint_model import detect_framing

    return detect_framing(b"".join(payloads))


def semantics_intact(original_packets, mutated_packets, client_ip=None) -> bool:
    """True only when the recovered CLIENT stream is byte-for-byte identical.

    This is the ONE strict bar (Fix 3), delegated to
    ``c2_semantics.bytes_equal_semantics`` so the training reward and the honest
    evaluation cannot drift apart.  The previous, relaxed bar parsed the command
    per packet and therefore accepted an HTTP header pad whose bytes the honest
    metric scores as a break -- which is exactly how the reward came to optimise
    for a mechanism the evaluation rejects.

    ``original_packets`` and ``mutated_packets`` are scapy packet lists (the
    stream is filtered to the client IP and IP fragments are reassembled).
    ``client_ip`` defaults to the bot derived from the packets; callers that
    know the flow id should pass ``client_ip_of(flow_id)`` explicitly so the
    identity matches the evaluation's exactly.
    """
    if client_ip is None:
        client_ip = client_ip_of_packets(original_packets)
    return bytes_equal_semantics(original_packets, mutated_packets, client_ip)


def mech_applicable(original_payloads, mech: str) -> bool:
    """False when the flow's protocol has nowhere for this mechanism to go.

    HTTP header padding cannot help a binary record chain; a length wrapper can
    only be read by a handler that already understands it.  Counting an
    inapplicable mechanism as an evasion would inflate every headline number.
    """
    from endpoint_model import detect_framing

    framing = detect_framing(b"".join(original_payloads))
    if mech in ("http_header_pad", "http_header_case"):
        return framing == "http"
    if mech == "length_wrapper":
        return framing == "length2"
    if mech == "split_slow":
        # Only meaningful when some payload exceeds the 8-byte fragment unit;
        # shorter payloads leave apply_mech a no-op, so it is inapplicable.
        return any(len(p) > 8 for p in original_payloads)
    if mech == "query_param_prepend":
        # P15: rewrites the request line by inserting a benign query parameter
        # after the '?'.  Nothing legal to do on a non-HTTP framing (mirrors the
        # apply_mech guard), and it is a no-op without a query string, so it is
        # inapplicable there rather than counted as an evasion or a failure.
        return framing == "http" and any(b"?" in p for p in original_payloads)
    return True


def apply_mech(pkts, mech: str, client_ip=None, ownership: str = "client"):
    """Apply a mechanism, touching the client's packets by default (Fix 2).

    ownership="client" (default) = conservative model, unchanged behavior.
    ownership="both" = allow rewriting BOTH endpoints' packets.  Under both,
    the byte-equality bar requires BOTH recovered streams to be identical
    (see c2_semantics.bytes_equal_semantics).  Invalid values raise ValueError.

    The attacker owns the client side of the session; rewriting the responder's
    bytes is outside the threat model.  The honest evaluation mutates
    client-only, so the training env must too -- otherwise semantics verdicts
    disagree.  The ``both`` mode is used only when explicitly opted into and
    the ceiling is measured with the two-sided bar.

    ``client_ip`` defaults to the bot derived from the packets; callers that
    know the flow id should pass ``client_ip_of(flow_id)`` so the identity
    matches the evaluation's exactly.  Rewrites IP/UDP/TCP checksums where a
    payload changed.
    """
    if ownership not in ("client", "both"):
        raise ValueError(f"ownership must be 'client' or 'both', got {ownership!r}")
    # ensure_chain: a lazily unpickled packet answers `IP in p` with False,
    # which would empty client_idx and turn the mechanism into a silent no-op
    # (it would "not evade" for a reason unrelated to evasion).
    out = [ensure_chain(p).copy() for p in pkts]
    if client_ip is None:
        client_ip = client_ip_of_packets(out)
    sip = None
    if ownership == "both":
        sip = server_ip_of(out, client_ip)
    client_idx = [i for i, p in enumerate(out)
                  if IP in p and p[IP].src == client_ip]
    pay_idx = [i for i in client_idx
               if has_payload(out[i])]

    own_idx = list(client_idx)          # every packet the model may touch
    tgt_idx = list(pay_idx)             # payload-bearing subset of own_idx
    if ownership == "both":
        srv_idx = [i for i, p in enumerate(out)
                   if IP in p and sip is not None and p[IP].src == sip]
        srv_pay = [i for i in srv_idx
                   if has_payload(out[i])]
        own_idx = sorted(set(client_idx) | set(srv_idx))
        tgt_idx = list(pay_idx) + list(srv_pay)

    if mech == "split_slow":
        # Ordinary byte-safe fragmentation, but the tail is held back past
        # frag3's default 60s timeout so the head fragment expires before
        # reassembly completes.  Bytes and offsets are untouched, so the
        # byte-equality bar passes by construction.  Intercepted BEFORE the
        # generic `startswith("split")` branch below, which would otherwise
        # try int("slow").
        from fragment_ops import fragment_plan_to_packets, make_slow_fragments
        rebuilt = []
        for i, p in enumerate(out):
            out_frags = None
            if i in tgt_idx:
                payload = transport_payload(p)
                if 0 < 8 < len(payload):
                    try:
                        out_frags = fragment_plan_to_packets(
                            out, make_slow_fragments(payload, 8), i)
                    except ValueError:
                        out_frags = None
            if out_frags is not None:
                # Apply the per-fragment delay as a real timestamp gap so
                # frag3's timeout window actually sees the separation.
                base = float(getattr(p, "time", 0.0) or 0.0)
                t = base
                for f in out_frags:
                    f.time = t
                    t += 75.0
                rebuilt.extend(out_frags)
            else:
                rebuilt.append(p)
        return rebuilt

    if mech.startswith("split"):
        from fragment_ops import fragment_plan_to_packets, split_fragments
        off = int(mech[5:])
        rebuilt = []
        for i, p in enumerate(out):
            out_frags = None
            if i in tgt_idx:
                payload = transport_payload(p)
                if 0 < off < len(payload):
                    try:
                        out_frags = fragment_plan_to_packets(out, split_fragments(payload, off), i)
                    except ValueError:
                        out_frags = None   # không có hình học hợp lệ: giữ packet
            if out_frags is not None:
                rebuilt.extend(out_frags)
            else:
                rebuilt.append(p)
        return rebuilt

    if mech == "overlap8":
        from fragment_ops import fragment_plan_to_packets, overlap_fragments
        rebuilt = []
        for i, p in enumerate(out):
            out_frags = None
            if i in tgt_idx:
                payload = transport_payload(p)
                if 8 < len(payload):
                    try:
                        out_frags = fragment_plan_to_packets(out, overlap_fragments(payload, 8), i)
                    except ValueError:
                        out_frags = None
            if out_frags is not None:
                rebuilt.extend(out_frags)
            else:
                rebuilt.append(p)
        return rebuilt

    if mech == "http_header_pad":
        # Mechanism A.  Junk goes into HTTP HEADERS, never in front of the
        # request line and never into a binary record chain -- a real server
        # skips an unknown header, but prepending breaks the request line.
        from endpoint_model import is_http_request

        for i in tgt_idx:
            p = as_raw(out[i])
            raw = bytes(p[Raw].load)
            if not is_http_request(raw):
                continue
            head, sep, body = raw.partition(b"\r\n")
            if not sep:
                continue
            p[Raw].load = head + b"\r\n" + _JUNK_HEADERS + body

    elif mech == "http_header_case":
        # RFC 7230 s3.2: HTTP field NAMES are case-insensitive, so folding the
        # name changes the wire but not the request's meaning.  Breaks Snort
        # rule SID 2012627 (FakeAV C2 check-in), which matches `Accept|3a 20|`
        # case-SENSITIVELY as part of a 4-content distance:0 adjacency chain.
        # This is a property of the ET Open ruleset signature, not a general
        # technique: folding the name moves those bytes out of the match while
        # leaving the request line and body untouched.  Nothing legal goes
        # after the request line on a non-HTTP framing, so guard on
        # is_http_request like the pad mech.
        from endpoint_model import is_http_request

        for i in tgt_idx:
            p = as_raw(out[i])
            raw = bytes(p[Raw].load)
            if not is_http_request(raw):
                continue
            head, sep, body = raw.partition(b"\r\n\r\n")
            if not sep:
                continue
            p[Raw].load = _lower_field_names(head) + b"\r\n\r\n" + body

    elif mech == "query_param_prepend":
        # Mirror of eval_pipeline.mutate_client_only (Fix 3 byte-identity):
        # insert one benign query parameter after the '?' to break literal
        # content-chains anchored on "<path>?<firstkey>=" (sid:2012533),
        # while a standard query parser still recovers the same parameters.
        # Request line lives on the client side, so pay_idx (client payload)
        # regardless of ownership -- identical bytes in both modes.  EVERY
        # request-bearing packet is rewritten (captures may repeat the same
        # GET in one flow; Snort alerts on either copy).
        from endpoint_model import is_http_request

        for i in pay_idx:
            p = as_raw(out[i])
            raw = bytes(p[Raw].load)
            if not is_http_request(raw):
                continue
            head, sep, rest = raw.partition(b"\r\n")
            if not sep:
                continue
            parts = head.split(b" ")
            if len(parts) < 2 or b"?" not in parts[1]:
                continue
            uri = parts[1]
            q = uri.index(b"?")
            parts[1] = uri[:q + 1] + b"x=0&" + uri[q + 1:]
            p[Raw].load = b" ".join(parts) + sep + rest

    elif mech == "length_wrapper":
        # Mechanism B.  A wrapper header declares where the real data starts,
        # so any amount of filler precedes it.  Applied to the first
        # payload-bearing CLIENT packet, which is where the stream begins.
        from fragment_ops import fix_checksums

        for i in tgt_idx:
            p = as_raw(out[i])
            raw = bytes(p[Raw].load)
            header = b"LEN%d:" % _WRAP_OFFSET
            out[i] = fix_checksums(p, header + bytes(_WRAP_OFFSET) + raw)
            break

    elif mech.startswith("pad"):
        n = int(mech[3:])
        for i in tgt_idx:
            p = as_raw(out[i])
            p[Raw].load = bytes(p[Raw].load) + bytes(n)

    elif mech.startswith("prepend"):
        n = int(mech[7:])
        for i in tgt_idx:
            p = as_raw(out[i])
            p[Raw].load = bytes(n) + bytes(p[Raw].load)

    elif mech.startswith("corrupt"):
        k = int(mech[7:])
        for i in tgt_idx:
            p = as_raw(out[i])
            pl = bytearray(bytes(p[Raw].load))
            for j in range(min(k, len(pl))):
                pl[j] = (j * 97 + 13) % 256
            p[Raw].load = bytes(pl)

    elif mech == "reorder":
        if len(own_idx) >= 3:
            a, b = own_idx[1], own_idx[2]
            out[a], out[b] = out[b], out[a]

    elif mech == "ttl":
        for i in own_idx:
            if IP in out[i]:
                out[i][IP].ttl = 33

    elif mech == "noop":
        pass

    if mech not in ("reorder", "ttl", "noop"):
        for p in out:
            if Raw not in p:
                continue
            if IP in p:
                del p[IP].chksum
            if UDP in p:
                del p[UDP].chksum
            elif TCP in p:
                del p[TCP].chksum
    else:
        for p in out:
            if IP in p:
                del p[IP].chksum
    return out


def load_corpus(split: str = "train", capture: str | None = None,
                 corpus: str | None = None):
    """Load flows, optionally restricted to one capture.

    ``split="all"`` pools train+test; combined with ``capture`` it yields the
    flow set for one leave-one-capture-out direction (train on A, test on B).
    ``corpus`` overrides the pickle path so a rebuilt corpus can be measured
    without editing CORPUS_PKL.
    """
    path = Path(corpus) if corpus else CORPUS_PKL
    with open(path, "rb") as fh:
        data = pickle.load(fh)
    flows = (data["train"] + data["test"]) if split == "all" else data[split]
    if capture:
        flows = [f for f in flows if f.get("capture") == capture]
        if not flows:
            raise ValueError(f"no flows for split={split!r} capture={capture!r}")
    return flows


# Framing/affordance block appended to every observation.  Without it the
# policy cannot tell an HTTP flow from a neris record stream, so the only
# representable policy is a constant that the mask clips per framing -- which
# is exactly the 2-action collapse this fixes.  Three features (one-hot over the
# two shipped framings + the HTTP-only affordance bit the mask uses for
# actions 12/13); 8 shallow + 3 = OBS_DIM=11.
_FRAMING_ONEHOT = ("http", "neris")


def framing_features(flow) -> list:
    """One-hot framing + the affordance bit the mask actually uses.

    The mask opens actions 12/13 (http_header_pad, length_wrapper) only for
    ``http`` and closes actions 3..5 (prepend*) for ``neris``; both gates are a
    function of the framing, so the HTTP-only bit plus the one-hot exposes the
    whole legal-action decision to the policy.
    """
    framing = flow.get("framing", "unknown")
    onehot = [1.0 if framing == name else 0.0 for name in _FRAMING_ONEHOT]
    http_only_ok = 1.0 if framing == "http" else 0.0        # mask[12], mask[13]
    return onehot + [http_only_ok]


class HiddenDefenderEnv(gym.Env):
    """One flow per episode; the agent never observes the ruleset."""

    metadata = {"render_modes": []}

    def __init__(self, split: str = "train", real_snort: bool = False,
                 seed: int = 42, max_steps: int = 1,
                 capture: str | None = None, ownership: str = "client",
                 corpus: str | None = None):
        super().__init__()
        self.split = split
        self.capture = capture
        if ownership not in ("client", "both"):
            raise ValueError(
                f"ownership must be 'client' or 'both', got {ownership!r}")
        self.ownership = ownership
        self._flows = load_corpus(split, capture, corpus)
        self.real_snort = real_snort
        self._svc = SnortBatchService(batch_size=1) if real_snort else None
        self.max_steps = max_steps
        self._rng = np.random.default_rng(seed)

        self.action_space = spaces.Discrete(N_ACTIONS)
        self.observation_space = spaces.Box(low=0.0, high=1.0,
                                            shape=(OBS_DIM,), dtype=np.float32)
        self._idx = 0
        self._last = None

    # -- scoring ----------------------------------------------------------
    def _detected(self, flow, pkts) -> bool:
        """True when the defender fires.  Replica or the real Snort binary."""
        if self.real_snort:
            svc = self._svc
            assert svc is not None
            res = svc.verdicts_chunked([(pkts, 0)])
            return bool(res.get(0, True))
        return bool(flow["replica"].verdict(pkts))

    def score(self, flow, mech: str):
        """Return (evaded, semantics_ok, alert) for one (flow, mechanism).

        Uses the SAME client-only mutation and the SAME strict byte-equality
        bar as the honest evaluation (Fix 2 + Fix 3), so the reward cannot
        optimise for a mechanism the evaluation scores as a semantics break.
        """
        pkts = flow["packets"]
        fid = flow.get("flow_id")
        cip = client_ip_of(fid) if fid else None
        mut = apply_mech(pkts, mech, cip, ownership=self.ownership)
        sem = semantics_intact(pkts, mut, cip)
        alert = self._detected(flow, mut)
        return (not alert), sem, alert

    # -- gym API ----------------------------------------------------------
    def _owned_payloads(self, flow):
        """Transport payloads of the packets the attacker may rewrite.

        Under ownership="client" that is the client's packets; under "both" the
        server's too.  Used by the mask so split_slow's applicability is judged
        on exactly the packets apply_mech would fragment.
        """
        pkts = flow["packets"]
        cip = client_ip_of(flow["flow_id"])
        ips = {cip}
        if self.ownership == "both":
            sip = server_ip_of(pkts, cip)
            if sip is not None:
                ips.add(sip)
        out = []
        for p in pkts:
            if IP in p and p[IP].src in ips:
                pl = transport_payload(p)
                if pl:
                    out.append(pl)
        return out

    def _compute_action_mask(self) -> list:
        """Direction 2: Compute which actions are applicable for current flow's protocol.
        
        Returns a list of N_ACTIONS binary values (0/1) where:
        - 1 = action is applicable (semantics-preserving for this protocol)
        - 0 = action is not applicable (would break semantics or be protocol-invalid)
        
        Rules:
        - noop (11) is always allowed
        - http_header_pad (12) only on HTTP
        - length_wrapper (13) only on HTTP (needs body to wrap)
        - split_slow (14) only when an owned packet has transport payload > 8
        - http_header_case (15) only on HTTP (P15)
        - query_param_prepend (16) only on HTTP and only with a '?' in an owned
          payload (P15; mirrors mech_applicable and the apply_mech guard)
        - All split/prepend/ttl/reorder/overlap actions apply to any protocol (IP layer)
        """
        if self._idx >= len(self._flows):
            return [1] * N_ACTIONS  # Default: all allowed if out of bounds
        
        flow = self._flows[self._idx]
        framing = flow.get("framing", "unknown")
        
        # Start: all actions allowed
        mask = [1] * N_ACTIONS
        
        # HTTP-only actions
        if framing != "http":
            mask[12] = 0  # http_header_pad requires HTTP
            mask[13] = 0  # length_wrapper requires HTTP body
            mask[15] = 0  # http_header_case requires HTTP (P15)
            mask[16] = 0  # query_param_prepend requires HTTP (P15)
        
        # neris-specific: prepend breaks the record chain parser
        # (conservative: only allow protocol-agnostic IP-layer mechanisms)
        if framing == "neris":
            mask[3] = 0   # prepend4
            mask[4] = 0   # prepend8
            mask[5] = 0   # prepend12
        
        # split_slow needs an owned packet whose transport payload exceeds the
        # 8-byte fragment unit; otherwise apply_mech is a no-op.  Mirrors the
        # condition inside apply_mech: `0 < 8 < len(payload)`.
        if not any(len(p) > 8 for p in self._owned_payloads(flow)):
            mask[14] = 0  # split_slow
        
        # query_param_prepend needs a '?' in an owned payload (mirrors
        # mech_applicable); without one apply_mech is a no-op.  (P15)
        if not any(b"?" in p for p in self._owned_payloads(flow)):
            mask[16] = 0  # query_param_prepend
        
        return mask

    def action_masks(self) -> np.ndarray:
        """Direction 2, wired for MaskablePPO.

        sb3-contrib's MaskablePPO requires the env to expose ``action_masks()``
        and calls it immediately before sampling an action, so the mask always
        reflects the flow the agent is actually facing.  Returning the mask in
        ``info`` from ``reset()`` is not enough: a plain ``PPO`` policy never
        reads it, and even a masking policy would see a stale mask after the
        first step of a multi-flow episode.
        """
        return np.asarray(self._compute_action_mask(), dtype=np.int8)

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        # Training must not re-walk the same first n_steps flows every epoch:
        # with n_steps=64 that was 64/1153 flows and the policy learned the
        # corpus prefix, not the corpus.  The test split stays frozen so
        # evaluation is comparable run to run.
        if self.split == "train":
            self._rng.shuffle(self._flows)
        self._idx = 0
        mask = self._compute_action_mask()
        return self._obs(), {"action_mask": mask}

    def _obs(self) -> np.ndarray:
        if self._idx >= len(self._flows):
            return np.zeros(OBS_DIM, dtype=np.float32)
        flow = self._flows[self._idx]
        base = flow["obs"]
        return np.asarray(list(base) + framing_features(flow), dtype=np.float32)

    def step(self, action: int):
        flow = self._flows[self._idx]
        mech = ACTION_NAMES[int(action)]
        evaded, sem, alert = self.score(flow, mech)

        # Base reward from evasion success/failure
        if evaded and sem:
            reward = REWARD_EVADE
        elif evaded and not sem:
            reward = REWARD_BREAK_SEMANTICS
        else:
            reward = REWARD_ALERTED

        # Subtract action cost (Direction 1): penalize expensive mechanisms.
        # This forces RL to learn trade-offs: "cheap actions are better when they work."
        action_cost = ACTION_COSTS[int(action)]
        reward = reward - action_cost

        # Tiny protocol-appropriate preference.  The generic split mechanisms
        # work on every framing, so on a mixed corpus they are a global optimum
        # and the policy collapses onto them, never sampling the cheaper
        # HTTP-native primitive on the flows where it applies.  This bonus is
        # granted ONLY when the action already produced a valid evasion, so it
        # cannot manufacture evasion or mask a failing mechanism.
        if evaded and sem:
            framing = flow.get("framing", "unknown")
            if mech in PROTOCOL_APPROPRIATE.get(framing, ()):
                reward += PROTOCOL_MATCH_BONUS

        self._idx += 1
        terminated = self._idx >= len(self._flows)
        truncated = False
        info = {
            "alert": alert,
            "evaded": evaded,
            "semantics_ok": sem,
            "action": mech,
            "flow_id": flow["flow_id"],
            "action_cost": action_cost,
        }
        if terminated:
            obs = np.zeros(OBS_DIM, dtype=np.float32)
        else:
            obs = self._obs()
        return np.asarray(obs, dtype=np.float32), reward, terminated, truncated, info

    def service_stats(self):
        return self._svc.stats() if self._svc else None
