"""
TLS cipher-suite reference data.

This module answers a *factual* question -- what does suite code 0xc030 denote -- and
never a security one. Whether ECDHE is acceptable and static RSA is not is a judgement,
and judgements live in `analysis/`.

CLOSED WORLD. `analysis/rules/tls_rules.py` deferred suite grading in Phase 4 on the
grounds that "a half-populated table would silently mislabel unknown suites". That
objection is answered structurally, not by aspiring to completeness: `lookup()` returns
None for any code not listed, and every caller must turn None into AMBIGUOUS. There is no
default, no nearest match and no "probably fine". A partial table is safe precisely
because "unknown" is a first-class answer.

PROVENANCE, in two deliberately separate blocks:

  _MODERN  -- generated from `openssl ciphers -V -stdname -s ALL:COMPLEMENTOFALL`
              (OpenSSL 3.6.3, 2026-09-22). 68 suites.
  _LEGACY  -- hand-curated from the IANA TLS Cipher Suite registry and the RFCs cited
              per entry.

The second block is not optional padding, and the reason is a measured trap: OpenSSL 3.6
ships **zero** suites containing NULL, EXPORT, RC4, DES, 3DES or MD5 -- it removed them
all. A table generated only from OpenSSL would therefore return "unknown" for exactly the
suites this tool most needs to name, and a weak-crypto finding would silently degrade to
AMBIGUOUS on the traffic that matters. The legacy block exists to close that gap.

Key exchange and authentication are PARSED FROM THE IANA NAME, not stored. The name
encodes them unambiguously (`TLS_ECDHE_RSA_WITH_...` -> ECDHE, RSA), whereas OpenSSL's own
Kx column reports `Kx=ECDH` for both ephemeral ECDHE and static ECDH -- a conflation that
would misreport forward secrecy, which is the one property D-17 exists to assess.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

#: IANA registry snapshot backing the hand-curated block.
IANA_REGISTRY_SNAPSHOT = "2026-09-22"
#: Generator for the _MODERN block, recorded so the table can be regenerated exactly.
MODERN_SOURCE = "openssl 3.6.3: ciphers -V -stdname -s ALL:COMPLEMENTOFALL"


# code -> (IANA name, encryption, MAC)
_MODERN: Dict[int, Tuple[str, str, str]] = {
    0x002f: ('TLS_RSA_WITH_AES_128_CBC_SHA', 'AES(128)', 'SHA1'),
    0x0032: ('TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 'AES(128)', 'SHA1'),
    0x0033: ('TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'AES(128)', 'SHA1'),
    0x0035: ('TLS_RSA_WITH_AES_256_CBC_SHA', 'AES(256)', 'SHA1'),
    0x0038: ('TLS_DHE_DSS_WITH_AES_256_CBC_SHA', 'AES(256)', 'SHA1'),
    0x0039: ('TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'AES(256)', 'SHA1'),
    0x003c: ('TLS_RSA_WITH_AES_128_CBC_SHA256', 'AES(128)', 'SHA256'),
    0x003d: ('TLS_RSA_WITH_AES_256_CBC_SHA256', 'AES(256)', 'SHA256'),
    0x0040: ('TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', 'AES(128)', 'SHA256'),
    0x0041: ('TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', 'Camellia(128)', 'SHA1'),
    0x0044: ('TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 'Camellia(128)', 'SHA1'),
    0x0045: ('TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', 'Camellia(128)', 'SHA1'),
    0x0067: ('TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'AES(128)', 'SHA256'),
    0x006a: ('TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', 'AES(256)', 'SHA256'),
    0x006b: ('TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'AES(256)', 'SHA256'),
    0x0084: ('TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'Camellia(256)', 'SHA1'),
    0x0087: ('TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', 'Camellia(256)', 'SHA1'),
    0x0088: ('TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'Camellia(256)', 'SHA1'),
    0x009c: ('TLS_RSA_WITH_AES_128_GCM_SHA256', 'AESGCM(128)', 'AEAD'),
    0x009d: ('TLS_RSA_WITH_AES_256_GCM_SHA384', 'AESGCM(256)', 'AEAD'),
    0x009e: ('TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'AESGCM(128)', 'AEAD'),
    0x009f: ('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'AESGCM(256)', 'AEAD'),
    0x00a2: ('TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', 'AESGCM(128)', 'AEAD'),
    0x00a3: ('TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', 'AESGCM(256)', 'AEAD'),
    0x00ba: ('TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'Camellia(128)', 'SHA256'),
    0x00bd: ('TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256', 'Camellia(128)', 'SHA256'),
    0x00be: ('TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'Camellia(128)', 'SHA256'),
    0x00c0: ('TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'Camellia(256)', 'SHA256'),
    0x00c3: ('TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256', 'Camellia(256)', 'SHA256'),
    0x00c4: ('TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'Camellia(256)', 'SHA256'),
    0x1301: ('TLS_AES_128_GCM_SHA256', 'AESGCM(128)', 'AEAD'),
    0x1302: ('TLS_AES_256_GCM_SHA384', 'AESGCM(256)', 'AEAD'),
    0x1303: ('TLS_CHACHA20_POLY1305_SHA256', 'CHACHA20/POLY1305(256)', 'AEAD'),
    0xc009: ('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'AES(128)', 'SHA1'),
    0xc00a: ('TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'AES(256)', 'SHA1'),
    0xc013: ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'AES(128)', 'SHA1'),
    0xc014: ('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'AES(256)', 'SHA1'),
    0xc023: ('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'AES(128)', 'SHA256'),
    0xc024: ('TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'AES(256)', 'SHA384'),
    0xc027: ('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'AES(128)', 'SHA256'),
    0xc028: ('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'AES(256)', 'SHA384'),
    0xc02b: ('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'AESGCM(128)', 'AEAD'),
    0xc02c: ('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'AESGCM(256)', 'AEAD'),
    0xc02f: ('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'AESGCM(128)', 'AEAD'),
    0xc030: ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'AESGCM(256)', 'AEAD'),
    0xc050: ('TLS_RSA_WITH_ARIA_128_GCM_SHA256', 'ARIAGCM(128)', 'AEAD'),
    0xc051: ('TLS_RSA_WITH_ARIA_256_GCM_SHA384', 'ARIAGCM(256)', 'AEAD'),
    0xc052: ('TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256', 'ARIAGCM(128)', 'AEAD'),
    0xc053: ('TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384', 'ARIAGCM(256)', 'AEAD'),
    0xc056: ('TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256', 'ARIAGCM(128)', 'AEAD'),
    0xc057: ('TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384', 'ARIAGCM(256)', 'AEAD'),
    0xc05c: ('TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256', 'ARIAGCM(128)', 'AEAD'),
    0xc05d: ('TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384', 'ARIAGCM(256)', 'AEAD'),
    0xc060: ('TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256', 'ARIAGCM(128)', 'AEAD'),
    0xc061: ('TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384', 'ARIAGCM(256)', 'AEAD'),
    0xc072: ('TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', 'Camellia(128)', 'SHA256'),
    0xc073: ('TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', 'Camellia(256)', 'SHA384'),
    0xc076: ('TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'Camellia(128)', 'SHA256'),
    0xc077: ('TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384', 'Camellia(256)', 'SHA384'),
    0xc09c: ('TLS_RSA_WITH_AES_128_CCM', 'AESCCM(128)', 'AEAD'),
    0xc09d: ('TLS_RSA_WITH_AES_256_CCM', 'AESCCM(256)', 'AEAD'),
    0xc09e: ('TLS_DHE_RSA_WITH_AES_128_CCM', 'AESCCM(128)', 'AEAD'),
    0xc09f: ('TLS_DHE_RSA_WITH_AES_256_CCM', 'AESCCM(256)', 'AEAD'),
    0xc0ac: ('TLS_ECDHE_ECDSA_WITH_AES_128_CCM', 'AESCCM(128)', 'AEAD'),
    0xc0ad: ('TLS_ECDHE_ECDSA_WITH_AES_256_CCM', 'AESCCM(256)', 'AEAD'),
    0xcca8: ('TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'CHACHA20/POLY1305(256)', 'AEAD'),
    0xcca9: ('TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'CHACHA20/POLY1305(256)', 'AEAD'),
    0xccaa: ('TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'CHACHA20/POLY1305(256)', 'AEAD'),
}

# Suites OpenSSL 3.x no longer ships. Each is a real registry entry, and each is here
# because its absence would be a silent detection gap rather than a cosmetic one.
_LEGACY: Dict[int, Tuple[str, str, str]] = {
    # RFC 5246 App. A.5 -- the null suite; no encryption whatsoever.
    0x0000: ("TLS_NULL_WITH_NULL_NULL", "NULL", "NULL"),
    # RFC 5246 App. A.5 -- authentication without confidentiality.
    0x0001: ("TLS_RSA_WITH_NULL_MD5", "NULL", "MD5"),
    0x0002: ("TLS_RSA_WITH_NULL_SHA", "NULL", "SHA1"),
    0x003b: ("TLS_RSA_WITH_NULL_SHA256", "NULL", "SHA256"),
    # RFC 4346 App. A.5 -- 40-bit export grade, broken by construction (FREAK).
    0x0003: ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RC4(40)", "MD5"),
    0x0008: ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "DES(40)", "SHA1"),
    0x0014: ("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "DES(40)", "SHA1"),
    # RFC 7465 prohibits RC4 in all TLS versions.
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RC4(128)", "MD5"),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RC4(128)", "SHA1"),
    0xc011: ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "RC4(128)", "SHA1"),
    0xc007: ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "RC4(128)", "SHA1"),
    # RFC 5246 App. A.5 -- single DES, 56-bit effective.
    0x0009: ("TLS_RSA_WITH_DES_CBC_SHA", "DES(56)", "SHA1"),
    0x0015: ("TLS_DHE_RSA_WITH_DES_CBC_SHA", "DES(56)", "SHA1"),
    # RFC 8996 SS5 / NIST SP 800-131A Rev.2 -- 3DES, 64-bit block (Sweet32).
    0x000a: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES(168)", "SHA1"),
    0x0016: ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES(168)", "SHA1"),
    0xc012: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES(168)", "SHA1"),
    0xc008: ("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "3DES(168)", "SHA1"),
    # RFC 5246 App. A.5 -- anonymous DH: no authentication, trivially MITM-able.
    0x0018: ("TLS_DH_anon_WITH_RC4_128_MD5", "RC4(128)", "MD5"),
    0x001b: ("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "3DES(168)", "SHA1"),
    0x0034: ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "AES(128)", "SHA1"),
    0x003a: ("TLS_DH_anon_WITH_AES_256_CBC_SHA", "AES(256)", "SHA1"),
    # RFC 4492 SS6 -- STATIC ECDH. Named almost identically to ECDHE and is NOT
    # forward secret; this pair is the reason key exchange is parsed from the name.
    0xc001: ("TLS_ECDH_ECDSA_WITH_NULL_SHA", "NULL", "SHA1"),
    0xc003: ("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "3DES(168)", "SHA1"),
    0xc004: ("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "AES(128)", "SHA1"),
    0xc005: ("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "AES(256)", "SHA1"),
    0xc00b: ("TLS_ECDH_RSA_WITH_NULL_SHA", "NULL", "SHA1"),
    0xc00d: ("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "3DES(168)", "SHA1"),
    0xc00e: ("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "AES(128)", "SHA1"),
    0xc00f: ("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "AES(256)", "SHA1"),
}


#: One table. Legacy entries must not collide with generated ones.
SUITES: Dict[int, Tuple[str, str, str]] = dict(_MODERN)
for _code, _row in _LEGACY.items():
    if _code in SUITES:                     # pragma: no cover - guarded by a test
        raise RuntimeError(f"duplicate cipher suite definition for 0x{_code:04x}")
    SUITES[_code] = _row


# ---------------------------------------------------------------- key exchange
#: IANA key-exchange tokens, longest first so ECDHE is matched before ECDH and
#: DHE before DH. Getting this order wrong would report a static-ECDH suite as
#: ephemeral and claim forward secrecy that does not exist.
_KEX_TOKENS: Tuple[Tuple[str, str, bool], ...] = (
    # (name prefix after "TLS_", mechanism, is_ephemeral)
    ("ECDHE_ECDSA", "ECDHE", True),
    ("ECDHE_RSA", "ECDHE", True),
    ("ECDHE_PSK", "ECDHE", True),
    ("ECDH_ECDSA", "ECDH", False),          # STATIC ECDH -- not forward secret
    ("ECDH_RSA", "ECDH", False),            # STATIC ECDH -- not forward secret
    ("DHE_RSA", "DHE", True),
    ("DHE_DSS", "DHE", True),
    ("DHE_PSK", "DHE", True),
    ("DH_anon", "DH_anon", True),           # ephemeral but UNAUTHENTICATED
    ("DH_RSA", "DH", False),                # static DH -- not forward secret
    ("DH_DSS", "DH", False),                # static DH -- not forward secret
    ("RSA_EXPORT", "RSA", False),
    ("RSA_PSK", "RSA", False),
    ("SRP_SHA", "SRP", True),
    ("PSK", "PSK", False),
    ("KRB5", "KRB5", False),
    ("RSA", "RSA", False),                  # static RSA key transport
    ("NULL", "NULL", False),
)

#: Authentication token, read from the same name.
_AUTH_BY_KEX = {
    "ECDHE_ECDSA": "ECDSA", "ECDHE_RSA": "RSA", "ECDHE_PSK": "PSK",
    "ECDH_ECDSA": "ECDSA", "ECDH_RSA": "RSA",
    "DHE_RSA": "RSA", "DHE_DSS": "DSS", "DHE_PSK": "PSK",
    "DH_anon": "anon", "DH_RSA": "RSA", "DH_DSS": "DSS",
    "RSA_EXPORT": "RSA", "RSA_PSK": "PSK", "SRP_SHA": "SRP",
    "PSK": "PSK", "KRB5": "KRB5", "RSA": "RSA", "NULL": "NULL",
}


@dataclass(frozen=True)
class SuiteProfile:
    """What a cipher suite code denotes. Facts only -- no verdict."""

    code: int
    name: str                       # IANA standard name
    key_exchange: Optional[str]     # None for TLS 1.3: the suite does not encode it
    authentication: Optional[str]   # None for TLS 1.3, likewise
    encryption: str
    mac: str
    is_tls13: bool

    @property
    def hex_code(self) -> str:
        return f"0x{self.code:04x}"

    @property
    def is_ephemeral(self) -> Optional[bool]:
        """Whether the key exchange is ephemeral. None when the suite does not say.

        TLS 1.3 returns None deliberately: the suite carries no key exchange at all
        (RFC 8446 -- every TLS 1.3 suite is Kx=any), so forward secrecy for 1.3 is
        established from the protocol version, not from here. Returning True would
        give the right answer for the wrong reason and would hide the distinction.
        """
        if self.is_tls13:
            return None
        for token, _mech, ephemeral in _KEX_TOKENS:
            if self.name.startswith("TLS_" + token + "_"):
                return ephemeral
        return None


def _parse_kex(name: str) -> Tuple[Optional[str], Optional[str]]:
    if "_WITH_" not in name:                 # TLS 1.3 grammar: TLS_<AEAD>_<HASH>
        return None, None
    for token, mechanism, _ephemeral in _KEX_TOKENS:
        if name.startswith("TLS_" + token + "_"):
            return mechanism, _AUTH_BY_KEX[token]
    return None, None


def lookup(code: Optional[int]) -> Optional[SuiteProfile]:
    """Resolve a suite code. Returns None for anything not in the table.

    None means "this table does not know", NOT "this suite is fine". Callers must
    render it as AMBIGUOUS evidence.
    """
    if code is None:
        return None
    row = SUITES.get(code)
    if row is None:
        return None
    name, encryption, mac = row
    kex, auth = _parse_kex(name)
    return SuiteProfile(
        code=code, name=name, key_exchange=kex, authentication=auth,
        encryption=encryption, mac=mac, is_tls13="_WITH_" not in name)


def parse_code(raw: object) -> Optional[int]:
    """Normalise a tshark suite value ("0x1302", "4866", 4866) to an int."""
    if raw is None:
        return None
    if isinstance(raw, bool):                # bool is an int subclass; reject it
        return None
    if isinstance(raw, int):
        return raw
    text = str(raw).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None
