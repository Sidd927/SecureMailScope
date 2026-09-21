"""
X.509 certificate assembly from dissected fields (D-10 .. D-14).

Facts only. Whether a 1024-bit key is too small is a judgement and lives in `analysis/`.

THE ATTRIBUTION RULE, which is the whole reason this module is careful.

tshark's `-T ek` output is flat: a two-certificate chain yields one list per field, not
one object per certificate. Some of those lists have exactly one entry per certificate
and some do not, and the difference is not guessable -- it was measured
(docs/phase11/02 SS7.2). `basicConstraints cA` is the clearest trap: tshark emits it only
when TRUE, so a chain of [leaf CA:FALSE, root CA:TRUE] yields a single `true`. Pairing it
by index would hand the root's CA flag to the leaf and invert the entire chain reading.

So a value is attributed to a specific certificate ONLY when its list length is exactly
`n` (one per certificate) or `2n` (validity dates). Anything else is retained at chain
level and explicitly marked unattributed. `_take` enforces this; there is no bypass.

Chain structure is read from Subject/Authority Key Identifiers rather than distinguished
names. RFC 5280 SS4.2.1.1 provides the AKI for exactly this purpose, it is index-safe,
and DN text is not attributable in a chain at all.

SECURITY: every string here is attacker-controlled -- a subject CN is whatever the server
put on the wire. Values are length-capped, never interpreted, never used to build an
identifier, and never executed or rendered unescaped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from securemailscope.crypto import oids

#: A chain longer than this is treated as hostile input rather than a real chain.
MAX_CHAIN_LENGTH = 10
#: Attacker-controlled strings are capped; truncation is recorded, never silent.
MAX_TEXT_LENGTH = 256
#: Cap on SAN entries retained per certificate.
MAX_SAN_ENTRIES = 32

#: tshark renders utcTime as "2026-09-21 20:04:26 (UTC)".
_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")


def _cap(text: Optional[str]) -> Optional[str]:
    """Bound an attacker-controlled string, marking truncation visibly."""
    if text is None:
        return None
    text = str(text)
    return text if len(text) <= MAX_TEXT_LENGTH else text[:MAX_TEXT_LENGTH] + "...[truncated]"


def parse_timestamp(text: Optional[str]) -> Optional[int]:
    """Parse a tshark certificate timestamp to a UTC epoch, or None.

    Implemented without `datetime.strptime` locale surprises and without any
    wall-clock read: this converts a written date, it never asks what time it is.
    """
    if not text:
        return None
    match = _TIME_RE.match(str(text).strip())
    if not match:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return None
    # days from the proleptic Gregorian epoch (1970-01-01), civil-from-days algorithm
    y = year - (month <= 2)
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + hour * 3600 + minute * 60 + second


def rsa_key_bits(modulus: Optional[str]) -> Optional[int]:
    """Derive RSA key size from the modulus.

    No tshark field carries key length; it is the bit length of the modulus. tshark
    renders the modulus as colon-separated hex with a leading 0x00 sign byte when the
    high bit is set, which must be dropped or every key reads 8 bits too long.
    """
    if not modulus:
        return None
    octets = [o for o in str(modulus).split(":") if o]
    if not octets:
        return None
    try:
        values = [int(o, 16) for o in octets]
    except ValueError:
        return None
    while values and values[0] == 0:        # strip ASN.1 INTEGER sign padding
        values.pop(0)
    if not values:
        return None
    return (len(values) - 1) * 8 + values[0].bit_length()


@dataclass(frozen=True)
class CertificateEvidence:
    """One certificate, as far as the capture actually supports."""

    index: int                                   # 0 = leaf (RFC 5246 SS7.4.2 ordering)
    serial: Optional[str] = None
    version: Optional[str] = None
    not_before_epoch: Optional[int] = None
    not_after_epoch: Optional[int] = None
    not_before_text: Optional[str] = None
    not_after_text: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    key_bits: Optional[int] = None
    subject_key_id: Optional[str] = None
    authority_key_id: Optional[str] = None
    san_dns_names: Tuple[str, ...] = ()

    @property
    def is_self_signed(self) -> Optional[bool]:
        """AKI == SKI. None when either identifier is absent.

        This is a STRUCTURAL observation: the certificate says it was issued by the
        holder of its own key. It is not a trust verdict, and self-signed is not a
        synonym for malicious.
        """
        if not self.subject_key_id or not self.authority_key_id:
            return None
        return self.subject_key_id == self.authority_key_id


@dataclass(frozen=True)
class ChainEvidence:
    """The certificate chain as presented in the handshake."""

    certificates: Tuple[CertificateEvidence, ...] = ()
    #: Fields present in the capture that could NOT be tied to a certificate.
    unattributed: Tuple[str, ...] = ()
    #: Signature-algorithm OIDs seen anywhere in the chain (not per-certificate:
    #: each certificate contributes several, so the cardinality does not track n).
    signature_algorithm_oids: Tuple[str, ...] = ()
    truncated: bool = False
    notes: Tuple[str, ...] = ()

    @property
    def present(self) -> bool:
        return bool(self.certificates)

    @property
    def leaf(self) -> Optional[CertificateEvidence]:
        return self.certificates[0] if self.certificates else None

    @property
    def links(self) -> Tuple[bool, ...]:
        """For each adjacent pair, whether cert[i].AKI == cert[i+1].SKI.

        RFC 5280 SS4.2.1.1. This establishes that the chain as presented is internally
        consistent. It establishes NOTHING about trust: no trust anchor is present in a
        packet capture, so the chain is never "valid", only "linked" or "not linked".
        """
        out: List[bool] = []
        for i in range(len(self.certificates) - 1):
            a, b = self.certificates[i], self.certificates[i + 1]
            out.append(bool(a.authority_key_id and b.subject_key_id
                            and a.authority_key_id == b.subject_key_id))
        return tuple(out)


def _take(values: Sequence[str], count: int, index: int,
          per_cert: int = 1) -> Optional[str]:
    """Index-safe read. Returns None unless the cardinality proves attribution.

    This is the enforcement point for the attribution rule: a field whose length is
    not exactly `count * per_cert` is not attributable to certificate `index`, and the
    honest answer is no answer.
    """
    if count <= 0 or len(values) != count * per_cert:
        return None
    position = index * per_cert
    return values[position] if position < len(values) else None


def build_chain(fields: Mapping[str, Sequence[str]]) -> ChainEvidence:
    """Assemble a chain from the raw multi-valued fields of one Certificate message."""

    def get(name: str) -> Tuple[str, ...]:
        return tuple(fields.get(name) or ())

    # Certificate count anchor. `signedCertificate_element` looks like the natural
    # anchor but is a bare `null` for a single certificate and a list of nulls for a
    # chain, so its length is 0 exactly when one certificate is present. Serial numbers
    # are mandatory (RFC 5280 SS4.1.2.2), appear exactly once per certificate, and never
    # carry a null, which makes them the only reliable anchor.
    serials = get("serials")
    count = len(serials) or len(get("cert_elements"))
    if count == 0:
        return ChainEvidence()

    notes: List[str] = []
    truncated = False
    if count > MAX_CHAIN_LENGTH:
        notes.append(
            f"chain reports {count} certificates; only the first {MAX_CHAIN_LENGTH} were "
            "read (bounded to prevent resource exhaustion from a hostile capture)")
        count = MAX_CHAIN_LENGTH
        truncated = True

    versions = get("versions")
    utc_times = get("validity_utc")
    moduli = get("rsa_moduli")
    skis = get("subject_key_ids")
    akis = get("authority_key_ids")
    san_names = get("san_dns")
    dn_text = get("dn_text")
    algorithm_ids = get("algorithm_ids")

    # subjectAltName is attributable ONLY for a single-certificate chain, never by
    # cardinality. A leaf carrying two SAN entries in a two-certificate chain produces
    # len(san) == count purely by coincidence, and index-pairing then hands the leaf's
    # second SAN to the issuer -- measured happening on the fixture chain, where the
    # root CA (which has no SAN at all) was credited with "smtp.example.test".
    # Matching cardinality is not evidence of correspondence.
    san_attributable = count == 1

    # Distinguished-name TEXT is never attributed, at any chain length. tshark emits
    # each RDN component as a separate value with no marker for which DN it belongs to:
    # a single self-signed certificate yields ["mail.example.test", "SMS Probe",
    # "mail.example.test", "SMS Probe"] -- CN and O, for issuer and subject, in one
    # flat list. Reading [0] as the subject and [-1] as the issuer produced
    # issuer="SMS Probe", which is an Organization component, not an issuer identity.
    # Identity is reported from subjectAltName, which is unambiguous; subject and
    # issuer identity are reported as NOT observable rather than guessed.
    unattributed: List[str] = []
    if dn_text:
        unattributed.append("distinguished names")
    if algorithm_ids and len(algorithm_ids) != count:
        unattributed.append("signature algorithms")
    if san_names and not san_attributable:
        unattributed.append("subjectAltName entries")

    certificates: List[CertificateEvidence] = []
    for i in range(count):
        not_before_text = _take(utc_times, count, i, per_cert=2)
        after_position = i * 2 + 1
        not_after_text = (utc_times[after_position]
                          if len(utc_times) == count * 2 and after_position < len(utc_times)
                          else None)

        modulus = _take(moduli, count, i)
        key_bits = rsa_key_bits(modulus)
        # A modulus is present only for RSA keys; an EC key yields none, and claiming
        # "RSA" from its absence would be a fabrication.
        key_algorithm = "RSA" if modulus else None

        sans: Tuple[str, ...] = ()
        if san_attributable:
            sans = tuple(_cap(s) for s in san_names[:MAX_SAN_ENTRIES])

        certificates.append(CertificateEvidence(
            index=i,
            serial=_cap(_take(serials, count, i)),
            version=_take(versions, count, i),
            not_before_epoch=parse_timestamp(not_before_text),
            not_after_epoch=parse_timestamp(not_after_text),
            not_before_text=_cap(not_before_text),
            not_after_text=_cap(not_after_text),
            public_key_algorithm=key_algorithm,
            key_bits=key_bits,
            subject_key_id=_take(skis, count, i),
            authority_key_id=_take(akis, count, i),
            san_dns_names=tuple(s for s in sans if s),
        ))

    return ChainEvidence(
        certificates=tuple(certificates),
        unattributed=tuple(unattributed),
        signature_algorithm_oids=tuple(algorithm_ids),
        truncated=truncated,
        notes=tuple(notes),
    )


def strongest_signature_hash(chain: ChainEvidence) -> Optional[Tuple[str, str]]:
    """The weakest signature hash present in the chain, with its deprecation citation.

    Returns the WEAKEST rather than the strongest, because a chain is only as sound as
    its weakest signature. Named for what callers ask -- "is anything deprecated here".
    """
    worst: Optional[Tuple[str, str]] = None
    for oid in chain.signature_algorithm_oids:
        entry = oids.signature_algorithm(oid)
        if not entry:
            continue
        _name, _key_algorithm, hash_name = entry
        citation = oids.DEPRECATED_HASHES.get(hash_name)
        if citation and worst is None:
            worst = (hash_name, citation)
    return worst
