"""
Key-exchange and forward-secrecy derivation (D-09, D-17).

Two protocol generations, two genuinely different derivations. Conflating them is the
main correctness hazard here, so they are kept structurally apart:

  TLS <=1.2  the suite name encodes the key exchange (TLS_ECDHE_RSA_WITH_...), so the
             mechanism is read from the suite and the result is OBSERVED.
  TLS 1.3    the suite does NOT encode it. RFC 8446 decoupled them and every TLS 1.3
             suite is Kx=any, so the negotiated group comes from the ServerHello
             key_share extension instead.

Forward secrecy for TLS 1.3 is INFERRED, never OBSERVED: the capture shows a version,
and the property follows from the RFC. That distinction is not pedantry -- OBSERVED
means "present in the captured bytes", and a forward-secrecy property never is.
"""
from __future__ import annotations

from typing import Optional

from securemailscope.crypto.suites import SuiteProfile, lookup, parse_code
from securemailscope.evidence.states import EvidenceField

#: RFC 8446 SS4.2.7 / RFC 7919 -- TLS supported-groups registry.
NAMED_GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
    29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
    259: "ffdhe6144", 260: "ffdhe8192",
}

#: Groups below this offer less than ~112 bits of security (NIST SP 800-57 Pt.1 Rev.5).
_WEAK_GROUPS = {"secp160r1", "secp192r1"}

RFC8446_FS = ("RFC 8446 SS1.2 and App. D.5: TLS 1.3 removed static RSA and static "
              "Diffie-Hellman key exchange, so every TLS 1.3 suite is forward secret")


def named_group(raw: object) -> EvidenceField:
    """Resolve a ServerHello key_share group number to its registry name."""
    code = parse_code(raw)
    if code is None:
        return EvidenceField.unknown("no key_share group observed in the ServerHello")
    name = NAMED_GROUPS.get(code)
    if name is None:
        # An unregistered group is not a weak group. Say what was seen, nothing more.
        return EvidenceField.ambiguous(
            None, f"key_share group {code} is not in the supported-groups registry")
    return EvidenceField.observed(name, "negotiated group from the ServerHello key_share")


def key_exchange(version: Optional[str], suite_raw: object,
                 group_raw: object) -> EvidenceField:
    """Identify the key-exchange mechanism (D-09)."""
    profile = lookup(parse_code(suite_raw))

    if version == "TLS1.3":
        group = named_group(group_raw)
        if group.is_conclusive:
            return EvidenceField.observed(
                f"ECDHE ({group.value})",
                "TLS 1.3 negotiates the key exchange in the ServerHello key_share "
                "extension; the cipher suite does not encode it (RFC 8446)")
        # TLS 1.3 without a visible key_share: the mechanism is constrained by the
        # protocol but the specific group is not established.
        return EvidenceField.inferred(
            "ephemeral (EC)DHE",
            "RFC 8446 permits only ephemeral (EC)DHE or PSK key establishment, but no "
            "key_share group was observed so the specific group is not established")

    if profile is None:
        if parse_code(suite_raw) is None:
            return EvidenceField.unknown("no cipher suite observed in a ServerHello")
        return EvidenceField.ambiguous(
            None, f"cipher suite {parse_code(suite_raw):#06x} is not in the reference "
                  "table, so its key exchange cannot be identified")

    if profile.key_exchange is None:
        return EvidenceField.ambiguous(
            None, f"{profile.name} does not encode a key-exchange mechanism")

    return EvidenceField.observed(
        profile.key_exchange,
        f"key exchange encoded in the negotiated cipher suite {profile.name}")


def forward_secrecy(version: Optional[str], suite_raw: object,
                    group_raw: object) -> EvidenceField:
    """Assess forward secrecy (D-17).

    Never returns False from missing evidence. An unobserved handshake yields UNKNOWN,
    which is a different claim from "not forward secret" -- and the difference is the
    whole point of the requirement.
    """
    if version == "TLS1.3":
        return EvidenceField.inferred(True, RFC8446_FS)

    code = parse_code(suite_raw)
    if code is None:
        return EvidenceField.unknown(
            "no cipher suite was observed, so forward secrecy cannot be assessed")

    profile = lookup(code)
    if profile is None:
        return EvidenceField.ambiguous(
            None, f"cipher suite {code:#06x} is not in the reference table; an "
                  "unrecognised suite is not treated as lacking forward secrecy")

    ephemeral = profile.is_ephemeral
    if ephemeral is None:
        return EvidenceField.ambiguous(
            None, f"{profile.name} does not encode a key-exchange mechanism")

    if ephemeral:
        return EvidenceField.observed(
            True, f"{profile.name} uses an ephemeral key exchange "
                  f"({profile.key_exchange}), which provides forward secrecy")
    return EvidenceField.observed(
        False, f"{profile.name} uses {profile.key_exchange} key exchange, which is not "
               "ephemeral: recovery of the server's long-term private key would expose "
               "this session")


def suite_name(suite_raw: object) -> EvidenceField:
    """Resolve the suite code to its IANA standard name."""
    code = parse_code(suite_raw)
    if code is None:
        return EvidenceField.unknown("no cipher suite observed in a ServerHello")
    profile = lookup(code)
    if profile is None:
        return EvidenceField.ambiguous(
            None, f"cipher suite {code:#06x} is not in the reference table")
    return EvidenceField.observed(
        profile.name, f"IANA standard name for suite {profile.hex_code}")


def is_weak_group(name: Optional[str]) -> bool:
    return name in _WEAK_GROUPS
