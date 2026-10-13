"""Lazy-unpickle landmine: `X in pkt` is False on a freshly loaded packet.

scapy restores a packet's layer chain lazily.  When `scapy.all` was never
imported in the process, the chain comes back EMPTY, so every membership test
(`IP in pkt`, `Raw in pkt`) answers False and the packet looks like bare
ethernet with no payload at all.  Every mechanism and every endpoint bar then
treats the whole flow as empty -- silently, with no error.

Reproduced deterministically on the extended corpus: flow
`...3653->60.190.223.75:888|tcp` reassembles to 315 bytes with
`from scapy.all import IP` executed first, and to b"" without it.  The bar then
reports "command not preserved" and the mechanism reports "not evaded" for a
reason that has nothing to do with evasion.
"""
import pickle
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SNORT_DIR = str(REPO / "snort_validation")
AGENT_DIR = str(REPO / "ai_agent")
PAYLOAD = b"GET /list.php?c=ABCDEF0123&v=2 HTTP/1.0\r\nHost: h\r\n\r\n"
SRC = "10.0.2.15"
DST = "198.51.100.7"


def _probe_code(blob: str) -> str:
    """Run in a FRESH interpreter that never imports scapy.all by itself."""
    return (
        "import pickle, sys\n"
        f"sys.path.insert(0, {SNORT_DIR!r})\n"
        f"sys.path.insert(0, {AGENT_DIR!r})\n"
        "import c2_semantics as cs\n"
        "from eval_pipeline import mutate_client_only\n"
        f"pk = pickle.loads(open({blob!r}, 'rb').read())\n"
        "out = {}\n"
        "out['IP in pkt'] = __import__('scapy.all', fromlist=['IP']).IP in pk\n"
        "out['payload'] = len(cs.transport_payload(pk))\n"
        "out['reassembled'] = len(cs.reassembled_client_bytes([pk], %r))\n"
        "mut = mutate_client_only([pk], 'query_param_prepend', %r)\n"
        "out['mech_changed_bytes'] = sum(1 for a, b in zip([pk], mut)\n"
        "                              if bytes(a) != bytes(b))\n"
        "out['client_ip'] = cs.client_ip_of_packets([pk])\n"
        "print(out)\n" % (SRC, SRC)
    )


def _run(blob: Path) -> dict:
    proc = subprocess.run([sys.executable, "-c", _probe_code(str(blob))],
                          capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stderr
    return eval(proc.stdout.strip())


def test_measurements_survive_a_fresh_interpreter_without_preexisting_layers(tmp_path):
    from scapy.all import IP, TCP, Ether, Raw
    pkt = Ether() / IP(src=SRC, dst=DST) / TCP() / Raw(PAYLOAD)
    blob = tmp_path / "pkt.pkl"
    blob.write_bytes(pickle.dumps(pkt))

    got = _run(blob)
    # The symptom itself is scapy's and stays: membership tests on a lazily
    # restored packet answer False.  What our code must guarantee is that no
    # measurement ever consumes that empty chain.
    assert got["IP in pkt"] is False, f"scapy no longer lazy: {got}"
    assert got["payload"] == len(PAYLOAD), f"payload lost: {got}"
    assert got["reassembled"] == len(PAYLOAD), f"stream lost: {got}"
    assert got["client_ip"] == SRC, f"client lookup lost: {got}"
    assert got["mech_changed_bytes"] == 1, f"mechanism no-op: {got}"