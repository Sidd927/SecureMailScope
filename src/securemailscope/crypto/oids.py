"""
X.509 object identifiers.

Reference data only. Which hash a signature uses is a fact; whether that hash is
acceptable is a judgement, and judgements live in `analysis/`.

CLOSED WORLD, same contract as `suites.py`: an unlisted OID resolves to None and is
rendered as the numeric OID itself. An unknown algorithm is never guessed at, and never
silently treated as strong or as weak.

Sources: RFC 5280 (PKIX), RFC 8017 (PKCS#1 v2.2), RFC 5758 (ECDSA/DSA with SHA-2),
RFC 8410 (Ed25519/Ed448), RFC 5480 (EC named curves), RFC 9155 (SHA-1 deprecation).
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

#: Signature algorithm OID -> (display name, public-key algorithm, hash algorithm)
SIGNATURE_ALGORITHMS: Dict[str, Tuple[str, str, str]] = {
    # RFC 8017 App. A.2.4 -- RSASSA-PKCS1-v1_5
    "1.2.840.113549.1.1.2": ("md2WithRSAEncryption", "RSA", "MD2"),
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "RSA", "MD5"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "RSA", "SHA-1"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "RSA", "SHA-512"),
    "1.2.840.113549.1.1.14": ("sha224WithRSAEncryption", "RSA", "SHA-224"),
    # RFC 8017 App. A.2.3 -- the hash rides in the parameters, not the OID.
    "1.2.840.113549.1.1.10": ("rsassaPss", "RSA", "PSS-parameterised"),
    # RFC 5758 SS3.2 -- ECDSA
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "EC", "SHA-1"),
    "1.2.840.10045.4.3.1": ("ecdsa-with-SHA224", "EC", "SHA-224"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "EC", "SHA-256"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "EC", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "EC", "SHA-512"),
    # RFC 5758 SS3.1 -- DSA
    "1.2.840.10040.4.3": ("dsa-with-sha1", "DSA", "SHA-1"),
    "2.16.840.1.101.3.4.3.2": ("dsa-with-sha256", "DSA", "SHA-256"),
    # RFC 8410 SS3 -- EdDSA; the hash is intrinsic to the algorithm.
    "1.3.101.112": ("Ed25519", "Ed25519", "SHA-512 (intrinsic)"),
    "1.3.101.113": ("Ed448", "Ed448", "SHAKE256 (intrinsic)"),
}

#: Public-key algorithm OID -> display name (RFC 5280 SS4.1.2.7, RFC 5480 SS2.1.1)
PUBLIC_KEY_ALGORITHMS: Dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.113549.1.3.1": "DH",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

#: Named elliptic curve OID -> (name, approximate security strength in bits)
NAMED_CURVES: Dict[str, Tuple[str, int]] = {
    "1.2.840.10045.3.1.1": ("secp192r1", 96),
    "1.3.132.0.33": ("secp224r1", 112),
    "1.2.840.10045.3.1.7": ("secp256r1", 128),
    "1.3.132.0.34": ("secp384r1", 192),
    "1.3.132.0.35": ("secp521r1", 256),
    "1.3.132.0.10": ("secp256k1", 128),
}

#: Certificate extension OID -> display name (RFC 5280 SS4.2)
EXTENSIONS: Dict[str, str] = {
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.17": "subjectAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.37": "extKeyUsage",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList",
}

#: Extended key usage OID -> display name (RFC 5280 SS4.2.1.12)
EXTENDED_KEY_USAGES: Dict[str, str] = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
}

#: Hashes prohibited for certificate signatures, with the citation for each.
#: Presence here is a FACT about deprecation status, quoted from the standard; the
#: severity attached to it is decided in `analysis/`, not here.
DEPRECATED_HASHES: Dict[str, str] = {
    "MD2": "RFC 6149: MD2 is obsolete and must not be used",
    "MD5": "RFC 6151: MD5 is not suitable for signature applications",
    "SHA-1": ("RFC 9155 and NIST SP 800-131A Rev.2: SHA-1 must not be used for "
              "digital signature generation"),
}


def signature_algorithm(oid: Optional[str]) -> Optional[Tuple[str, str, str]]:
    return SIGNATURE_ALGORITHMS.get(oid) if oid else None


def public_key_algorithm(oid: Optional[str]) -> Optional[str]:
    return PUBLIC_KEY_ALGORITHMS.get(oid) if oid else None


def named_curve(oid: Optional[str]) -> Optional[Tuple[str, int]]:
    return NAMED_CURVES.get(oid) if oid else None


def describe(oid: Optional[str]) -> Optional[str]:
    """Best display name for any known OID; the numeric OID itself when unknown."""
    if not oid:
        return None
    for table in (EXTENSIONS, EXTENDED_KEY_USAGES, PUBLIC_KEY_ALGORITHMS):
        if oid in table:
            return table[oid]
    if oid in SIGNATURE_ALGORITHMS:
        return SIGNATURE_ALGORITHMS[oid][0]
    if oid in NAMED_CURVES:
        return NAMED_CURVES[oid][0]
    return oid
