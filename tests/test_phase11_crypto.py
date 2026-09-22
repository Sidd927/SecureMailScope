"""
Phase-11 crypto layer: adversarial and regression tests.

These target the specific ways this code could lie rather than merely break. A bug that
raises is found immediately; a bug that confidently reports "forward secrecy: absent"
for a handshake nobody saw is the kind this project exists to prevent, so those are the
cases asserted here.
"""
import time

import pytest

from securemailscope.crypto import certificates as C
from securemailscope.crypto import keyexchange as K
from securemailscope.crypto import oids, suites
from securemailscope.evidence.states import EvidenceState


# =========================================================== the suite table
def test_table_is_closed_world():
    """An unlisted suite must yield None, never a default or a nearest match.

    tls_rules.py deferred suite grading in Phase 4 because "a half-populated table
    would silently mislabel unknown suites". This is the structural answer.
    """
    for code in (0xFFFF, 0xDEAD, 0x9999, -1, 10**9):
        assert suites.lookup(code) is None, hex(code) if code > 0 else code


def test_modern_and_legacy_blocks_do_not_collide():
    """A duplicate definition would let one block silently shadow the other."""
    modern = set(suites._MODERN)
    legacy = set(suites._LEGACY)
    assert modern & legacy == set(), sorted(modern & legacy)


def test_legacy_block_covers_what_openssl_removed():
    """OpenSSL 3.6 ships zero NULL/EXPORT/RC4/DES/3DES/MD5 suites.

    A table generated only from OpenSSL would return "unknown" for exactly the suites
    this tool most needs to name, and a weak-crypto finding would silently degrade to
    AMBIGUOUS on the traffic that matters most.
    """
    for token in ("NULL", "EXPORT", "RC4", "3DES", "MD5", "DH_anon"):
        named = [n for n, _e, _m in suites.SUITES.values() if token in n]
        assert named, token


@pytest.mark.parametrize("code,expected", [
    (0xc030, "ECDHE"),          # ephemeral ECDH
    (0xc00f, "ECDH"),           # STATIC ECDH -- one letter apart, opposite meaning
    (0x002f, "RSA"),            # static RSA key transport
    (0x0033, "DHE"),
    (0x0034, "DH_anon"),
])
def test_key_exchange_is_parsed_from_the_iana_name(code, expected):
    assert suites.lookup(code).key_exchange == expected


def test_static_ecdh_is_not_mistaken_for_ephemeral():
    """The single most dangerous confusion in this module.

    OpenSSL's own Kx column reports `Kx=ECDH` for BOTH ephemeral ECDHE and static
    ECDH. Trusting it would claim forward secrecy for suites that have none, which is
    precisely the property D-17 exists to assess.
    """
    assert suites.lookup(0xc030).is_ephemeral is True      # TLS_ECDHE_RSA_...
    assert suites.lookup(0xc00f).is_ephemeral is False     # TLS_ECDH_RSA_...
    assert suites.lookup(0xc005).is_ephemeral is False     # TLS_ECDH_ECDSA_...


def test_tls13_suites_report_no_key_exchange():
    """RFC 8446: every TLS 1.3 suite is Kx=any.

    `is_ephemeral` returns None rather than True on purpose. True would be the right
    answer for the wrong reason and would hide that the suite carries no key exchange
    at all -- the group comes from key_share.
    """
    for code in (0x1301, 0x1302, 0x1303):
        profile = suites.lookup(code)
        assert profile.is_tls13 is True
        assert profile.key_exchange is None
        assert profile.is_ephemeral is None


def test_parse_code_rejects_junk_rather_than_guessing():
    assert suites.parse_code("0x1302") == 0x1302
    assert suites.parse_code("4866") == 4866
    for junk in (None, "", "zzz", "0xZZ", True, False, [1]):
        assert suites.parse_code(junk) is None, junk


# ===================================================== forward secrecy safety
def test_forward_secrecy_is_never_false_without_a_handshake():
    """THE forbidden conversion for D-17.

    "We could not see the handshake" and "there was no forward secrecy" are different
    claims. Collapsing them would invent a security finding out of a capture gap.
    """
    field = K.forward_secrecy(None, None, None)
    assert field.state is EvidenceState.UNKNOWN
    assert field.value is None


def test_unknown_suite_never_reports_absent_forward_secrecy():
    field = K.forward_secrecy("TLS1.2", "0xffff", None)
    assert field.state is EvidenceState.AMBIGUOUS
    assert field.value is None
    assert "not treated as lacking forward secrecy" in field.basis


def test_tls13_forward_secrecy_is_inferred_not_observed():
    """The capture shows a version; the property follows from the RFC.

    OBSERVED means "present in the captured bytes", and a forward-secrecy property
    never is. Marking it OBSERVED would be the small dishonesty the evidence model
    exists to prevent.
    """
    field = K.forward_secrecy("TLS1.3", "0x1302", "29")
    assert field.state is EvidenceState.INFERRED
    assert field.value is True
    assert "RFC 8446" in field.basis


def test_static_key_exchange_reports_absent_forward_secrecy():
    field = K.forward_secrecy("TLS1.2", "0x002f", None)
    assert field.state is EvidenceState.OBSERVED
    assert field.value is False
    assert "long-term private key" in field.basis


def test_tls13_key_exchange_comes_from_key_share_not_the_suite():
    with_group = K.key_exchange("TLS1.3", "0x1302", "29")
    assert with_group.state is EvidenceState.OBSERVED
    assert "x25519" in with_group.value

    # no key_share observed: the mechanism is constrained by the protocol, but the
    # specific group is not established, so this is INFERRED and says so.
    without = K.key_exchange("TLS1.3", "0x1302", None)
    assert without.state is EvidenceState.INFERRED
    assert "no key_share group was observed" in without.basis


def test_unregistered_group_is_ambiguous_not_weak():
    field = K.named_group("31337")
    assert field.state is EvidenceState.AMBIGUOUS
    assert field.value is None


# ============================================================ key length maths
@pytest.mark.parametrize("octets,expected", [
    (256, 2048),      # RSA-2048: 256 octets after the sign byte
    (128, 1024),      # RSA-1024
    (512, 4096),      # RSA-4096
])
def test_rsa_key_bits_strips_the_sign_byte(octets, expected):
    """The leading 00 is ASN.1 INTEGER sign padding, not key material.

    Counting it would report every key with a high top bit as 8 bits longer than it
    is -- which would push a 1016-bit key over the 1024 line and, more importantly,
    make key-length findings wrong in the direction of reassurance.
    """
    # high bit set in the first real octet, so ASN.1 requires the 00 pad
    modulus = ":".join(["00", "bd"] + ["ff"] * (octets - 1))
    assert C.rsa_key_bits(modulus) == expected


def test_rsa_key_bits_counts_the_leading_octet_exactly():
    """A short top octet shortens the key; the length is not rounded up to a byte."""
    assert C.rsa_key_bits("01" + ":ff" * 3) == 25      # 1 + 24
    assert C.rsa_key_bits("ff" + ":ff" * 3) == 32


def test_rsa_key_bits_refuses_junk():
    for junk in (None, "", "zz:zz", ":::"):
        assert C.rsa_key_bits(junk) is None, junk


# =============================================================== timestamps
def test_timestamp_parsing_round_trips_against_the_stdlib():
    """The parser is hand-rolled to avoid locale surprises and any wall-clock read.

    Expectations are computed with `calendar.timegm` rather than written as literals,
    so this checks the parser against an INDEPENDENT implementation. (Written as
    literals first, two of the four were wrong -- the parser was right.)
    """
    import calendar
    import datetime
    for stamp in ("2026-09-21 20:04:26", "1970-01-01 00:00:00",
                  "2000-02-29 12:00:00",     # leap year
                  "2100-03-01 00:00:00",     # 2100 is NOT a leap year
                  "1999-12-31 23:59:59", "2038-01-19 03:14:08"):  # past 32-bit time_t
        expected = calendar.timegm(
            datetime.datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").timetuple())
        assert C.parse_timestamp(stamp + " (UTC)") == expected, stamp


def test_timestamp_parsing_refuses_junk():
    for junk in (None, "", "0", "not a date", "2026-13-45 00:00:00"):
        assert C.parse_timestamp(junk) is None, junk


def test_choice_selector_is_not_parsed_as_a_date():
    """tshark emits notBefore/notAfter as ASN.1 CHOICE selectors ("0" = utcTime).

    The pre-Phase-11 field map pointed at those keys, so expiry would have been
    computed from the string "0". Parsing must reject it rather than yield epoch 0,
    which would make every certificate look expired since 1970.
    """
    assert C.parse_timestamp("0") is None


# ================================================== the attribution rule
def _fields(**kw):
    return {k: tuple(v) for k, v in kw.items()}


def test_single_certificate_is_anchored_by_serial_not_by_element():
    """`signedCertificate_element` is a bare null for one certificate, so its length
    is zero exactly when one certificate is present. Serials are mandatory."""
    chain = C.build_chain(_fields(serials=["aa:bb"], cert_elements=[],
                                  validity_utc=["2026-01-01 00:00:00 (UTC)",
                                                "2027-01-01 00:00:00 (UTC)"]))
    assert len(chain.certificates) == 1
    assert chain.certificates[0].not_after_epoch is not None


def test_san_is_not_index_paired_across_a_chain():
    """MEASURED DEFECT. A leaf with two SAN entries in a two-certificate chain gives
    len(san) == count purely by coincidence; index-pairing credited the root CA --
    which has no SAN at all -- with the leaf's second name.

    Matching cardinality is not evidence of correspondence.
    """
    chain = C.build_chain(_fields(
        serials=["aa", "bb"],
        san_dns=["mail.example.test", "smtp.example.test"]))
    assert len(chain.certificates) == 2
    for cert in chain.certificates:
        assert cert.san_dns_names == ()
    assert "subjectAltName entries" in chain.unattributed


def test_san_is_attributed_for_a_single_certificate():
    chain = C.build_chain(_fields(serials=["aa"],
                                  san_dns=["mail.example.test", "imap.example.test"]))
    assert chain.certificates[0].san_dns_names == ("mail.example.test",
                                                   "imap.example.test")


def test_distinguished_name_text_is_never_attributed():
    """MEASURED FABRICATION. dn_text for one self-signed certificate is
    [CN, O, CN, O] with no marker for which DN each belongs to. Reading [0] as the
    subject and [-1] as the issuer reported issuer="SecureMailScope Probe", which is
    an Organization component, not an issuer identity.
    """
    chain = C.build_chain(_fields(
        serials=["aa"],
        dn_text=["mail.example.test", "SMS Probe", "mail.example.test", "SMS Probe"]))
    cert = chain.certificates[0]
    assert not hasattr(cert, "subject_text")
    assert not hasattr(cert, "issuer_text")
    assert "distinguished names" in chain.unattributed


def test_mismatched_cardinality_yields_no_value_rather_than_a_guess():
    chain = C.build_chain(_fields(serials=["aa", "bb"], versions=["2"]))  # 1 != 2
    for cert in chain.certificates:
        assert cert.version is None


# ================================================== chain structure semantics
def test_self_signed_is_detected_from_key_identifiers():
    chain = C.build_chain(_fields(serials=["aa"], subject_key_ids=["ab:cd"],
                                  authority_key_ids=["ab:cd"]))
    assert chain.certificates[0].is_self_signed is True


def test_self_signed_is_undetermined_without_identifiers():
    """Absent identifiers must not read as "not self-signed"."""
    chain = C.build_chain(_fields(serials=["aa"]))
    assert chain.certificates[0].is_self_signed is None


def test_chain_links_follow_aki_to_ski():
    chain = C.build_chain(_fields(
        serials=["leaf", "ca"],
        subject_key_ids=["11:11", "22:22"],
        authority_key_ids=["22:22", "22:22"]))
    assert chain.links == (True,)
    assert chain.certificates[0].is_self_signed is False
    assert chain.certificates[1].is_self_signed is True


def test_broken_link_is_reported_as_unlinked_not_invalid():
    chain = C.build_chain(_fields(
        serials=["leaf", "other"],
        subject_key_ids=["11:11", "33:33"],
        authority_key_ids=["22:22", "33:33"]))
    assert chain.links == (False,)


# ========================================================= hostile input bounds
def test_chain_length_is_bounded():
    """A capture claiming thousands of certificates is a resource-exhaustion vector."""
    n = C.MAX_CHAIN_LENGTH + 50
    chain = C.build_chain(_fields(serials=[f"{i:02x}" for i in range(n)]))
    assert len(chain.certificates) == C.MAX_CHAIN_LENGTH
    assert chain.truncated is True
    assert chain.notes and "bounded" in chain.notes[0]


def test_attacker_controlled_text_is_capped_and_marked():
    hostile = "A" * (C.MAX_TEXT_LENGTH * 4)
    chain = C.build_chain(_fields(serials=[hostile]))
    serial = chain.certificates[0].serial
    assert len(serial) < len(hostile)
    assert serial.endswith("...[truncated]")


def test_san_entry_count_is_bounded():
    many = [f"host{i}.example.test" for i in range(C.MAX_SAN_ENTRIES * 3)]
    chain = C.build_chain(_fields(serials=["aa"], san_dns=many))
    assert len(chain.certificates[0].san_dns_names) <= C.MAX_SAN_ENTRIES


def test_empty_input_yields_no_chain_rather_than_an_empty_certificate():
    assert C.build_chain({}).present is False
    assert C.build_chain(_fields(serials=[])).certificates == ()


# =============================================================== OID handling
def test_unknown_oid_renders_as_the_numeric_oid():
    """Never a guessed name, and never silently dropped."""
    assert oids.describe("1.2.3.4.5.6.7") == "1.2.3.4.5.6.7"
    assert oids.signature_algorithm("1.2.3.4.5.6.7") is None


def test_deprecated_hashes_carry_a_citation():
    for hash_name in ("MD2", "MD5", "SHA-1"):
        citation = oids.DEPRECATED_HASHES[hash_name]
        assert any(token in citation for token in ("RFC", "NIST")), hash_name


def test_sha256_is_not_deprecated():
    assert "SHA-256" not in oids.DEPRECATED_HASHES
    name, _key, hash_name = oids.signature_algorithm("1.2.840.113549.1.1.11")
    assert name == "sha256WithRSAEncryption"
    assert oids.DEPRECATED_HASHES.get(hash_name) is None


def test_weakest_chain_signature_is_reported():
    chain = C.build_chain(_fields(
        serials=["aa"],
        algorithm_ids=["1.2.840.113549.1.1.11",    # SHA-256
                       "1.2.840.113549.1.1.5"]))   # SHA-1  <- the weak one
    found = C.strongest_signature_hash(chain)
    assert found is not None and found[0] == "SHA-1"


# ================================================================ determinism
def test_derivations_are_pure_and_deterministic():
    """No clock, no randomness: the same input must give the same evidence twice.

    `assessment_id` is content-addressed, so any hidden time dependence here would
    break re-running an old capture.
    """
    args = ("TLS1.2", "0xc030", None)
    first = (K.key_exchange(*args), K.forward_secrecy(*args))
    time.sleep(0.01)
    second = (K.key_exchange(*args), K.forward_secrecy(*args))
    assert first == second
