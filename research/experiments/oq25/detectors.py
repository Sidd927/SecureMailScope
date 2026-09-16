"""
OQ-25 detectors.

D1  PER-SESSION  -- the naive competitor-style rule (CipherPost's rule_starttls_strip).
D2  CROSS-SESSION -- deterministic aggregation. No ML, no scores, documented transitions.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass

# verdicts
BENIGN      = "BENIGN"
SUSPECT     = "SUSPECT_DOWNGRADE"
UNKNOWN     = "UNKNOWN"
INSUFFICIENT= "INSUFFICIENT_HISTORY"

# cross-session infrastructure states
CONSISTENT_TLS       = "CONSISTENT_TLS"
CONSISTENT_PLAINTEXT = "CONSISTENT_PLAINTEXT"
ANOMALOUS            = "ANOMALOUS"
MIXED                = "MIXED"


# ---------------------------------------------------------------- D1
def d1_per_session(o) -> str:
    """
    Naive per-session detector, faithful to CipherPost:

        if saw_starttls_offer and not started_tls and not tls_bytes:
            -> "Possible STARTTLS stripping" (CRITICAL)

    What it CAN know: whether an advertisement, a command, and a handshake
    appeared in THIS session.
    What it CANNOT know: whether the advertisement was ever present upstream,
    whether this endpoint behaves differently elsewhere, or whether the capture
    is representative. Deliberately not weakened: this is the real rule.
    """
    if o.truncated:
        return UNKNOWN
    if o.starttls_advertised and not o.tls_handshake_observed:
        return SUSPECT
    return BENIGN


# ---------------------------------------------------------------- keys
def key_global(o):        return ("GLOBAL",)
def key_server(o):        return (o.server,)
def key_client(o):        return (o.client,)
def key_pair(o):          return (o.client, o.server)
def key_pair_proto(o):    return (o.client, o.server, o.protocol)
def key_server_proto(o):  return (o.server, o.protocol)

KEYS = {
    "global":        key_global,
    "server":        key_server,
    "client":        key_client,
    "pair":          key_pair,
    "pair+proto":    key_pair_proto,
    "server+proto":  key_server_proto,
}


@dataclass
class Stats:
    n: int = 0
    advertised: int = 0
    commanded: int = 0
    tls_ok: int = 0
    plaintext: int = 0
    failed: int = 0
    truncated: int = 0


def _collect(observations, keyfn):
    agg = defaultdict(Stats)
    for o in observations:
        s = agg[keyfn(o)]
        s.n += 1
        s.advertised += o.starttls_advertised
        s.commanded  += o.starttls_command_seen
        s.tls_ok     += o.tls_handshake_observed
        s.plaintext  += o.plaintext_continuation
        s.truncated  += o.truncated
        if o.starttls_command_seen and not o.tls_handshake_observed:
            s.failed += 1
    return agg


def infrastructure_state(s: Stats, min_history: int) -> str:
    """Deterministic state transitions. Every branch has a stated reason."""
    usable = s.n - s.truncated
    if usable < min_history:
        return INSUFFICIENT                     # not enough evidence to baseline
    if s.tls_ok == 0:
        return CONSISTENT_PLAINTEXT             # this endpoint NEVER upgrades
    if s.tls_ok == usable:
        return CONSISTENT_TLS                   # this endpoint ALWAYS upgrades
    return MIXED                                # both behaviours present


def d2_cross_session(observations, keyfn, min_history=5, server_index=None):
    """
    Cross-session reasoning.

    Rule set (deterministic):
      R1 truncated              -> UNKNOWN
      R2 TLS observed           -> BENIGN
      R3 insufficient history   -> INSUFFICIENT_HISTORY (explicitly NOT an accusation)
      R4 CONSISTENT_PLAINTEXT   -> BENIGN (configuration), UNLESS the same server
                                   is seen upgrading with some OTHER client (R6)
      R5 MIXED and this session lacks TLS -> SUSPECT (deviates from own baseline)
      R6 server-contrast override: server serves TLS to someone else but never to
         this client -> SUSPECT. This is the ONLY rule that can catch a fully
         stripped advertisement, and it needs a second client as a control.
    """
    agg = _collect(observations, keyfn)
    out = {}
    for o in observations:
        if o.truncated:
            out[o.session_id] = (UNKNOWN, "truncated capture"); continue
        if o.tls_handshake_observed:
            out[o.session_id] = (BENIGN, "TLS established"); continue

        s = agg[keyfn(o)]
        state = infrastructure_state(s, min_history)

        if state == INSUFFICIENT:
            out[o.session_id] = (INSUFFICIENT,
                                 f"only {s.n - s.truncated} usable sessions for key"); continue

        if state == CONSISTENT_PLAINTEXT:
            if server_index is not None:
                srv = server_index.get((o.server, o.protocol))
                if srv and srv.tls_ok > 0:
                    out[o.session_id] = (
                        SUSPECT,
                        f"server upgrades for other clients ({srv.tls_ok}/{srv.n}) "
                        f"but never for this one")
                    continue
            out[o.session_id] = (BENIGN,
                                 f"consistent plaintext across {s.n} sessions -> configuration")
            continue

        if state == MIXED:
            out[o.session_id] = (SUSPECT,
                                 f"deviates from own baseline ({s.tls_ok}/{s.n} upgrade)")
            continue

        out[o.session_id] = (SUSPECT, "no TLS despite consistent-TLS baseline")
    return out


def build_server_index(observations):
    return _collect(observations, key_server_proto)
