"""
OQ-25 corpus generator.

Emits SESSION OBSERVATIONS — the feature vector a passive PCAP parser would
recover from the cleartext phase of a mail session. Ground truth is carried in a
SEPARATE structure and is never visible to any detector.

SCOPE LIMITATION (stated up front, not buried):
This is a SESSION-MODEL experiment, not a packet-level one. We model the
observable outcome of each session rather than synthesising real PCAPs. That is
sufficient to test the OQ-25 hypothesis -- which is about REASONING over session
observations, not about parsing -- but it does NOT validate the parser, and it
cannot surface packet-level surprises (segmentation, pipelining, retransmits).
Packet-level validation remains the 01B S10 experiment.
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------- ground truth
LEGIT_TLS             = "LEGIT_TLS"              # normal: advertised, upgraded
LEGIT_DECLINE         = "LEGIT_DECLINE"          # client policy: never upgrades
LEGIT_PLAINTEXT_CFG   = "LEGIT_PLAINTEXT_CFG"    # server genuinely offers no STARTTLS
ATTACK_STRIP_ADVERT   = "ATTACK_STRIP_ADVERT"    # MITM removes the capability line
ATTACK_STRIP_COMMAND  = "ATTACK_STRIP_COMMAND"   # MITM errors/blocks the command
FAILED_UPGRADE        = "FAILED_UPGRADE"         # genuine TLS negotiation failure
INCOMPLETE_CAPTURE    = "INCOMPLETE_CAPTURE"     # truncated capture

ATTACKS = {ATTACK_STRIP_ADVERT, ATTACK_STRIP_COMMAND}


@dataclass
class Observation:
    """Strictly passive-observable features. No ground truth here."""
    session_id: str
    protocol: str                       # smtp | imap | pop3
    client: str
    server: str
    port: int
    day: int
    starttls_advertised: bool
    starttls_command_seen: bool
    starttls_response_code: Optional[str]   # '220'/'+OK'/'OK' | '454'/'-ERR'/'NO' | None
    tls_handshake_observed: bool
    tls_version: Optional[str]
    plaintext_continuation: bool
    truncated: bool
    bytes_total: int
    duration_ms: int


_ADV = {"smtp": "250-STARTTLS", "imap": "STARTTLS", "pop3": "STLS"}
_OK  = {"smtp": "220",          "imap": "OK",       "pop3": "+OK"}
_ERR = {"smtp": "454",          "imap": "NO",       "pop3": "-ERR"}


def emit(gt: str, *, sid: str, protocol: str, client: str, server: str,
         port: int, day: int, rng: random.Random) -> tuple[Observation, str]:
    """Map hidden ground truth -> passively observable features."""
    adv = cmd = tls = plain = trunc = False
    resp = None
    ver = None

    if gt == LEGIT_TLS:
        adv, cmd, tls = True, True, True
        resp, ver = _OK[protocol], rng.choice(["TLS1.2", "TLS1.3", "TLS1.3"])
    elif gt == LEGIT_DECLINE:
        # Server offers; client never asks. Continues in cleartext.
        adv, plain = True, True
    elif gt == LEGIT_PLAINTEXT_CFG:
        # Server never advertises. Cleartext by design.
        plain = True
    elif gt == ATTACK_STRIP_ADVERT:
        # MITM deletes the capability line. NOTE: observationally IDENTICAL
        # to LEGIT_PLAINTEXT_CFG at the single-session level. This is the crux.
        plain = True
    elif gt == ATTACK_STRIP_COMMAND:
        adv, cmd, plain = True, True, True
        resp = _ERR[protocol]
    elif gt == FAILED_UPGRADE:
        adv, cmd = True, True
        resp = _OK[protocol]          # 220 sent, handshake then fails
    elif gt == INCOMPLETE_CAPTURE:
        adv, trunc = True, True
    else:
        raise ValueError(gt)

    obs = Observation(
        session_id=sid, protocol=protocol, client=client, server=server,
        port=port, day=day,
        starttls_advertised=adv, starttls_command_seen=cmd,
        starttls_response_code=resp, tls_handshake_observed=tls,
        tls_version=ver, plaintext_continuation=plain, truncated=trunc,
        bytes_total=rng.randint(800, 9000), duration_ms=rng.randint(40, 2400),
    )
    return obs, gt


class Corpus:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.obs: list[Observation] = []
        self.truth: dict[str, str] = {}
        self._n = 0

    def add(self, gt: str, *, protocol="smtp", client="c1", server="s1",
            port=587, day=1, count=1):
        for _ in range(count):
            self._n += 1
            sid = f"S{self._n:05d}"
            o, t = emit(gt, sid=sid, protocol=protocol, client=client,
                        server=server, port=port, day=day, rng=self.rng)
            self.obs.append(o)
            self.truth[sid] = t
        return self

    def observations(self) -> list[Observation]:
        """What a detector is allowed to see."""
        return list(self.obs)

    def ground_truth(self, sid: str) -> str:
        return self.truth[sid]
