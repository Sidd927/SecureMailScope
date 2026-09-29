"""
X.509 certificate rules (PS deliverables D-10 .. D-14).

Standards basis (primary sources):
  * RFC 5280 -- PKIX certificate and CRL profile. SS6 defines path validation as an
    algorithm over a set of TRUST ANCHORS; SS4.2.1.1/4.2.1.2 define the Authority and
    Subject Key Identifiers used here for chain linkage.
  * RFC 6960 -- OCSP. A separate network transaction, absent from a mail capture.
  * RFC 9155 / NIST SP 800-131A Rev.2 -- SHA-1 is not permitted for signatures.
  * NIST SP 800-57 Part 1 Rev.5 SS5.6.1 -- RSA below 2048 bits gives under 112 bits of
    security and is disallowed.
  * RFC 8446 SS2 -- TLS 1.3 sends the Certificate message encrypted.

WHAT THIS MODULE WILL NOT DO, and why each is a deliberate refusal rather than an
unfinished feature:

  * It will not say a certificate is TRUSTED or UNTRUSTED. RFC 5280 SS6 needs trust
    anchors, and a packet capture contains none. Bundling a public root store was
    considered and rejected in ADR-0023: enterprise mail routinely uses private CAs, so
    it would mark legitimate deployments untrusted -- a systematic false positive on
    exactly the population this tool targets.
  * It will not say a certificate is REVOKED or NOT REVOKED. That needs OCSP or a CRL.
  * It will not treat a missing certificate as a certificate defect. Under TLS 1.3 the
    Certificate message is encrypted; in a resumed session it is never sent. Both are
    properties of the protocol, not of the certificate.
  * It will not compare expiry against the wall clock. See CertificateExpiryRule.
"""
from __future__ import annotations

from typing import List

from securemailscope.analysis.model import FindingStatus, SecurityFinding, Severity
from securemailscope.analysis.registry import SecurityRule, ref
from securemailscope.crypto import oids
from securemailscope.evidence.states import EvidenceState
from securemailscope.session.model import SessionEvidence, TlsState

RFC5280 = "RFC 5280: Internet X.509 PKI certificate and CRL profile"
RFC5280_PATH = ("RFC 5280 SS6: certification path validation requires a set of trust "
                "anchors, which a packet capture does not contain")
RFC5280_AKI = ("RFC 5280 SS4.2.1.1: the Authority Key Identifier identifies the key that "
               "signed a certificate, and is the intended means of chain building")
RFC6960 = ("RFC 6960: OCSP status is retrieved in a separate network transaction and is "
           "not present in a passively captured mail session")
RFC8446_ENCRYPTED = "RFC 8446 SS2: the TLS 1.3 Certificate message is encrypted"
NIST_KEYLEN = ("NIST SP 800-57 Part 1 Rev.5 SS5.6.1: RSA moduli below 2048 bits provide "
               "less than 112 bits of security and are disallowed")

#: NIST SP 800-57 Pt.1 Rev.5 -- minimum RSA modulus for >= 112-bit security.
MIN_RSA_BITS = 2048


def _has_tls(session: SessionEvidence) -> bool:
    return session.tls_state is not TlsState.NONE


def _absence_reason(session: SessionEvidence) -> str:
    """Why no certificate is available. The specific reason matters forensically.

    "Encrypted", "not sent" and "not captured" have different remediations and different
    evidential weight, so they are never collapsed into one "unavailable".
    """
    version = session.tls_negotiated_version.value_or(None)
    if version == "TLS1.3":
        return ("the negotiated TLS version encrypts the Certificate message, so it is "
                "structurally invisible to passive observation (RFC 8446 SS2)")
    if session.tls_state is TlsState.CLIENT_HELLO_OBSERVED:
        return ("only a ClientHello was captured, so the server's Certificate message "
                "was never observed")
    if session.tls_state is TlsState.HANDSHAKE_INTERRUPTED:
        return ("the handshake was interrupted before a Certificate message was "
                "observed; the capture is truncated at this point")
    if version is None:
        return ("no ServerHello was captured, so it cannot be established whether a "
                "Certificate message was sent")
    return ("no cleartext Certificate message appears in this stream, which also occurs "
            "whenever a session is resumed")


class CertificatePresenceRule(SecurityRule):
    """SEC-CERT-001 -- certificate extraction (D-10).

    Reports what was extracted, or the specific reason nothing was. Supersedes the
    presence half of SEC-TLS-003, which now covers only the trust boundary.
    """

    rule_id = "SEC-CERT-001"
    title = "Certificate extraction"
    description = ("Extracts X.509 certificates presented in a cleartext TLS handshake, "
                   "or reports why none is observable.")
    standards = (RFC5280, RFC8446_ENCRYPTED)

    def applies_to(self, session: SessionEvidence) -> bool:
        return _has_tls(session)

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        chain = session.tls_certificate_chain
        refs = [ref("tls_certificate_chain", chain),
                ref("tls_negotiated_version", session.tls_negotiated_version)]

        if not session.certificates:
            return [self.finding(
                session,
                status=FindingStatus.NOT_OBSERVABLE, severity=Severity.INFO,
                conclusion="No certificate was observable in this session.",
                explanation=(f"No certificate could be extracted because {_absence_reason(session)}. "
                             "This is not a finding about the certificate itself: absence of "
                             "certificate evidence is not evidence of an absent, invalid or "
                             "untrusted certificate."),
                evidence_refs=refs,
                limitations=(
                    "Under TLS 1.3 the Certificate message is encrypted and cannot be "
                    "recovered passively without key material.",
                    "Resumed sessions omit the Certificate message at any TLS version.",
                    "A capture started mid-session will not contain the handshake.",
                ))]

        count = len(session.certificates)
        leaf = session.certificates[0]
        names = ", ".join(leaf.san_dns_names) if leaf.san_dns_names else "none observed"
        return [self.finding(
            session,
            status=FindingStatus.INFORMATIONAL, severity=Severity.INFO,
            conclusion=(f"{count} certificate{'s' if count != 1 else ''} extracted from "
                        "the cleartext handshake."),
            explanation=(f"The handshake presented {count} certificate"
                         f"{'s' if count != 1 else ''} in cleartext. "
                         f"Leaf subjectAltName DNS entries: {names}. "
                         "Provenance: observed -- read directly from this session's "
                         "captured bytes, not retrieved from the server and not "
                         "recovered from an earlier session."),
            evidence_refs=refs,
            limitations=tuple(session.certificate_notes) + (
                "Subject and issuer identity are not reported: the dissector emits "
                "distinguished-name components without indicating which name they "
                "belong to, so attributing them would be a guess.",
            ))]


class CertificateExpiryRule(SecurityRule):
    """SEC-CERT-002 -- validity window (D-12).

    THE REFERENCE INSTANT IS THE CAPTURE TIMESTAMP, NEVER THE WALL CLOCK.

    Two independent reasons, either sufficient:
      1. Honesty. A capture from 2019 assessed today would report "expired" for
         certificates that were entirely valid when the traffic was recorded. A forensic
         tool reports what was true at capture time. The capture timestamp is itself
         observed evidence; the analyst's clock is not evidence at all.
      2. Determinism. `assessment_id` is content-addressed, so re-running the same PCAP
         next year must yield the same assessment. A wall-clock comparison would break
         that outright.
    """

    rule_id = "SEC-CERT-002"
    title = "Certificate validity period"
    description = ("Evaluates each certificate's validity window against the capture "
                   "timestamp.")
    standards = (RFC5280,)

    def applies_to(self, session: SessionEvidence) -> bool:
        return bool(session.certificates)

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        reference = session.start_epoch
        refs = [ref("tls_certificate_chain", session.tls_certificate_chain)]

        if reference is None:
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="Certificate validity could not be evaluated.",
                explanation=("The capture carries no timestamp for this session, so there "
                             "is no defensible reference instant. The current date is "
                             "deliberately NOT used: it would report certificates as "
                             "expired that were valid when the traffic was recorded."),
                evidence_refs=refs)]

        expired: List[str] = []
        not_yet: List[str] = []
        unknown = 0
        for cert in session.certificates:
            role = "leaf" if cert.index == 0 else f"issuer[{cert.index}]"
            if cert.not_after_epoch is None or cert.not_before_epoch is None:
                unknown += 1
                continue
            if reference > cert.not_after_epoch:
                expired.append(f"{role} expired {cert.not_after_text}")
            elif reference < cert.not_before_epoch:
                not_yet.append(f"{role} not valid until {cert.not_before_text}")

        when = ("the moment the traffic was captured "
                f"({_format_epoch(reference)}), not the current date")

        if expired or not_yet:
            detail = "; ".join(expired + not_yet)
            return [self.finding(
                session,
                status=FindingStatus.OBSERVED_ISSUE, severity=Severity.HIGH,
                conclusion="A certificate was outside its validity period during this session.",
                explanation=(f"Evaluated against {when}: {detail}. A client performing "
                             "RFC 5280 validation would reject this certificate."),
                evidence_refs=refs,
                remediation=("Renew the certificate and automate renewal so that expiry "
                             "cannot recur; verify the server clock if a certificate is "
                             "reported as not yet valid."),
                limitations=("Validity is assessed against the capture timestamp, so this "
                             "states the certificate's status at capture time, not now.",))]

        if unknown == len(session.certificates):
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="Certificate validity dates could not be read.",
                explanation="No validity window could be decoded from the captured bytes.",
                evidence_refs=refs)]

        return [self.finding(
            session,
            status=FindingStatus.COMPLIANT, severity=Severity.INFO,
            conclusion="All observed certificates were within their validity period.",
            explanation=f"Every extracted certificate was valid at {when}.",
            evidence_refs=refs,
            limitations=(("Some certificates carried no readable validity window."
                          ,) if unknown else ()))]


class CertificateKeyStrengthRule(SecurityRule):
    """SEC-CERT-003 -- public key algorithm and length (D-13)."""

    rule_id = "SEC-CERT-003"
    title = "Certificate public key strength"
    description = "Reports the public key algorithm and modulus length of each certificate."
    standards = (NIST_KEYLEN,)

    def applies_to(self, session: SessionEvidence) -> bool:
        return bool(session.certificates)

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        refs = [ref("tls_certificate_chain", session.tls_certificate_chain)]
        weak, described, unknown = [], [], 0

        for cert in session.certificates:
            role = "leaf" if cert.index == 0 else f"issuer[{cert.index}]"
            if cert.key_bits is None:
                unknown += 1
                continue
            described.append(f"{role}: {cert.public_key_algorithm}-{cert.key_bits}")
            if cert.public_key_algorithm == "RSA" and cert.key_bits < MIN_RSA_BITS:
                weak.append(f"{role} uses a {cert.key_bits}-bit RSA key")

        if weak:
            return [self.finding(
                session,
                status=FindingStatus.OBSERVED_ISSUE, severity=Severity.HIGH,
                conclusion="A certificate uses an RSA key below the permitted length.",
                explanation=("; ".join(weak) + f". {NIST_KEYLEN}."),
                evidence_refs=refs,
                remediation=("Reissue the certificate with an RSA key of at least 2048 "
                             "bits, or an ECDSA key on P-256 or stronger."),
                limitations=("Key length is derived from the modulus in the captured "
                             "certificate.",))]

        if not described:
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="Certificate key strength could not be determined.",
                explanation=("No public key parameters could be read. Non-RSA keys are "
                             "not reported as weak: an unread key is not a small key."),
                evidence_refs=refs)]

        return [self.finding(
            session,
            status=FindingStatus.COMPLIANT, severity=Severity.INFO,
            conclusion="Observed certificate keys meet the minimum length.",
            explanation="; ".join(described) + f". Minimum required: RSA {MIN_RSA_BITS} bits.",
            evidence_refs=refs,
            limitations=(("Some certificates carried no readable public key parameters."
                          ,) if unknown else ()))]


class CertificateSignatureRule(SecurityRule):
    """SEC-CERT-004 -- digital signature algorithm identification (D-14)."""

    rule_id = "SEC-CERT-004"
    title = "Certificate signature algorithm"
    description = "Identifies the signature algorithms used across the certificate chain."
    standards = ("RFC 9155: SHA-1 must not be used for digital signatures",
                 "NIST SP 800-131A Rev.2: SHA-1 signature generation is disallowed")

    def applies_to(self, session: SessionEvidence) -> bool:
        return bool(session.certificates)

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        refs = [ref("tls_certificate_chain", session.tls_certificate_chain)]

        names, deprecated = [], []
        for oid in session.chain_signature_oids:
            entry = oids.signature_algorithm(oid)
            if entry is None:
                continue
            name, _key_algorithm, hash_name = entry
            if name not in names:
                names.append(name)
            citation = oids.DEPRECATED_HASHES.get(hash_name)
            if citation and (hash_name, citation) not in deprecated:
                deprecated.append((hash_name, citation))

        if deprecated:
            detail = "; ".join(f"{h} -- {c}" for h, c in deprecated)
            return [self.finding(
                session,
                status=FindingStatus.OBSERVED_ISSUE, severity=Severity.HIGH,
                conclusion="A certificate in the chain is signed with a deprecated hash.",
                explanation=(f"Signature algorithms observed: {', '.join(names)}. {detail}. "
                             "A chain is only as sound as its weakest signature."),
                evidence_refs=refs,
                remediation=("Reissue the affected certificates with SHA-256 or stronger, "
                             "and confirm the issuing CA no longer signs with SHA-1."),
                limitations=("Signature algorithms are reported for the chain as a whole: "
                             "the dissector does not attribute them to individual "
                             "certificates reliably.",))]

        if not names:
            return [self.finding(
                session,
                status=FindingStatus.INSUFFICIENT_EVIDENCE, severity=Severity.INFO,
                conclusion="Certificate signature algorithms could not be identified.",
                explanation=("No recognised signature algorithm OID was read. An "
                             "unrecognised OID is reported as unidentified, never as weak."),
                evidence_refs=refs)]

        return [self.finding(
            session,
            status=FindingStatus.COMPLIANT, severity=Severity.INFO,
            conclusion="Certificate signature algorithms are current.",
            explanation=f"Signature algorithms observed: {', '.join(names)}.",
            evidence_refs=refs)]


class CertificateChainRule(SecurityRule):
    """SEC-CERT-005 -- chain structure (D-11, PARTIAL by construction).

    Delivers structural analysis and explicitly declines trust and revocation. The
    requirement closes PARTIAL, and this rule says so in the output rather than letting
    a reader infer that "chain validation" means trust was checked.
    """

    rule_id = "SEC-CERT-005"
    title = "Certificate chain structure"
    description = ("Analyses the structure of the presented chain: ordering, linkage, "
                   "and self-signing. Does not perform trust or revocation validation.")
    standards = (RFC5280_AKI, RFC5280_PATH, RFC6960)

    def applies_to(self, session: SessionEvidence) -> bool:
        return bool(session.certificates)

    def evaluate(self, session: SessionEvidence) -> List[SecurityFinding]:
        refs = [ref("tls_certificate_chain", session.tls_certificate_chain)]
        certs = session.certificates
        leaf = certs[0]
        links = session.chain_links

        boundary = (
            "Trust was NOT evaluated: RFC 5280 SS6 path validation requires trust "
            "anchors, and a packet capture contains none.",
            "Revocation was NOT checked: OCSP and CRL retrieval are separate network "
            "transactions absent from this capture.",
            "This analysis is structural only. A linked chain is not a trusted chain.",
        )

        # A self-signed leaf presented for a mail service is a real, evidenced
        # configuration condition -- but it is a configuration finding, not an
        # accusation. Self-signed is not a synonym for malicious.
        if len(certs) == 1 and leaf.is_self_signed is True:
            return [self.finding(
                session,
                status=FindingStatus.OBSERVED_ISSUE, severity=Severity.MEDIUM,
                conclusion="The server presented a single self-signed certificate.",
                explanation=("The leaf certificate's Authority Key Identifier equals its "
                             "Subject Key Identifier, so it was issued by the holder of "
                             "its own key, and no issuing chain was presented. Clients "
                             "performing standard validation will reject it unless it has "
                             "been installed as a trust anchor out of band. This is a "
                             "structural observation about configuration, not an "
                             "indication of malicious activity."),
                evidence_refs=refs,
                remediation=("Install a certificate issued by a CA the clients already "
                             "trust, or distribute the internal root to clients "
                             "deliberately if a private CA is intended."),
                limitations=boundary)]

        if len(certs) > 1 and links and not all(links):
            broken = [f"certificate {i} does not link to certificate {i + 1}"
                      for i, ok in enumerate(links) if not ok]
            return [self.finding(
                session,
                status=FindingStatus.AMBIGUOUS, severity=Severity.INFO,
                conclusion="The presented chain does not link end to end.",
                explanation=("; ".join(broken) + ". The Authority Key Identifier of one "
                             "certificate does not match the Subject Key Identifier of the "
                             "next. This may mean the chain is misordered or incomplete, or "
                             "that an identifier was not captured -- it is NOT a finding "
                             "that the chain is invalid."),
                evidence_refs=refs,
                limitations=boundary + (
                    "Servers are not required to send a complete chain; clients may "
                    "complete it from their own store or from authorityInfoAccess.",))]

        detail = f"{len(certs)} certificate{'s' if len(certs) != 1 else ''} presented"
        if links:
            detail += "; each certificate links to the next by Authority Key Identifier"
        return [self.finding(
            session,
            status=FindingStatus.INFORMATIONAL, severity=Severity.INFO,
            conclusion="Certificate chain structure analysed.",
            explanation=(f"{detail}. Structural analysis only -- see the limitations for "
                         "what was deliberately not assessed."),
            evidence_refs=refs,
            limitations=boundary)]


def _format_epoch(epoch: float) -> str:
    """Render a capture epoch as UTC, without importing a wall clock."""
    seconds = int(epoch)
    days, rem = divmod(seconds, 86400)
    hour, rem = divmod(rem, 3600)
    minute, second = divmod(rem, 60)
    # civil-from-days (Howard Hinnant), the inverse of the parser in crypto/certificates
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    y += (m <= 2)
    return f"{y:04d}-{m:02d}-{d:02d} {hour:02d}:{minute:02d}:{second:02d} UTC"
