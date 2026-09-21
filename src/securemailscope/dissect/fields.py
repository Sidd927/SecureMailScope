"""
tshark field-name map — the ONLY place tshark's schema is named.

Isolating these here means a tshark version change touches one file (ADR-0001
"Interface" risk). Names were discovered empirically against tshark 4.6.8 `-T ek`,
which nests fields one level under each protocol layer (layers.tcp.tcp_tcp_srcport).
We flatten before lookup, so both nested and flat layouts work.

Each entry lists alternatives in preference order; the first present wins. If none is
present the caller records the fact as UNKNOWN/NOT_OBSERVABLE -- never fabricated.
"""
from __future__ import annotations

# ---- frame / capture ------------------------------------------------------
FRAME_NUMBER = ("frame_frame_number",)
FRAME_TIME_EPOCH = ("frame_frame_time_epoch",)
FRAME_LEN = ("frame_frame_len", "frame_frame_cap_len")
FRAME_PROTOCOLS = ("frame_frame_protocols",)   # e.g. "eth:ethertype:ip:tcp:imap"

# ---- network / transport --------------------------------------------------
IP_SRC = ("ip_ip_src", "ipv6_ipv6_src")
IP_DST = ("ip_ip_dst", "ipv6_ipv6_dst")
SRC_PORT = ("tcp_tcp_srcport", "udp_udp_srcport")
DST_PORT = ("tcp_tcp_dstport", "udp_udp_dstport")
TCP_STREAM = ("tcp_tcp_stream",)               # stable per-capture stream index
TCP_SEQ = ("tcp_tcp_seq",)
TCP_FLAGS = ("tcp_tcp_flags",)
TCP_PAYLOAD = ("tcp_tcp_payload",)

# ---- TLS (evidence only; no security interpretation in this layer) ---------
TLS_RECORD_VERSION = ("tls_tls_record_version",)
TLS_HANDSHAKE_TYPE = ("tls_tls_handshake_type",)
TLS_HANDSHAKE_VERSION = ("tls_tls_handshake_version",)
TLS_CIPHERSUITE = ("tls_tls_handshake_ciphersuite",)
TLS_SNI = ("tls_tls_handshake_extensions_server_name",)
TLS_SUPPORTED_VERSION = ("tls_tls_handshake_extensions_supported_version",)
TLS_SESSION_ID = ("tls_tls_handshake_session_id",)
TLS_APP_DATA = ("tls_tls_app_data",)
#: TLS 1.3 negotiates the key exchange here, not in the cipher suite (RFC 8446 SS4.2.8).
TLS_KEY_SHARE_GROUP = ("tls_tls_handshake_extensions_key_share_group",)

# ---- X.509 (often absent: TLS 1.3 encrypts the Certificate message) -------
# Verified against real captures in Phase 11 (research/experiments/p11cert), including
# a two-certificate chain. Absence is represented explicitly as NOT_OBSERVABLE rather
# than assumed invalid (docs/architecture/04).
#
# CORRECTED IN PHASE 11. The previous mapping read
#     X509_NOT_BEFORE = ("x509af_x509af_utcTime",   "x509af_x509af_notBefore")
#     X509_NOT_AFTER  = ("x509af_x509af_utcTime_1", "x509af_x509af_notAfter")
# Both lines were wrong, and wrong in a way that only a real certificate would expose:
#   * tshark 4.6.8 emits no `_1`-suffixed keys at all, so NOT_AFTER fell through to
#     `x509af_x509af_notAfter`, which is the ASN.1 CHOICE selector ("0" = utcTime),
#     not a date. Expiry would have been computed from the string "0".
#   * The dates live in `x509af_x509af_utcTime` as an ORDERED LIST, two entries per
#     certificate: [leaf.notBefore, leaf.notAfter, issuer.notBefore, issuer.notAfter].
# The validity dates are therefore read positionally from one field, and the pairing
# rule lives in crypto/certificates.py where it can be guarded and tested.
X509_VALIDITY_UTC = ("x509af_x509af_utcTime",)
X509_VALIDITY_GENERALIZED = ("x509af_x509af_generalizedTime",)
#: Certificate count anchor: one entry per certificate in the chain.
X509_CERT_ELEMENT = ("x509af_x509af_signedCertificate_element",)
X509_SERIAL = ("x509af_x509af_serialNumber",)
X509_VERSION = ("x509af_x509af_version",)
X509_ALGORITHM_ID = ("x509af_x509af_algorithm_id",)
X509_RSA_MODULUS = ("pkixalgs_pkixalgs_modulus",)
X509_RSA_EXPONENT = ("pkixalgs_pkixalgs_publicExponent",)
#: RFC 5280 SS4.2.1.1/4.2.1.2 -- the index-safe way to establish chain linkage and
#: self-signing, used in preference to distinguished-name text (which is NOT
#: index-attributable in a multi-certificate chain; see docs/phase11/02 SS7.2).
X509_SUBJECT_KEY_ID = ("x509ce_x509ce_SubjectKeyIdentifier",)
X509_AUTHORITY_KEY_ID = ("x509ce_x509ce_keyIdentifier",)
X509_BASIC_CONSTRAINTS = ("x509ce_x509ce_BasicConstraintsSyntax_element",)
#: NOTE: tshark emits `cA` ONLY when true, so its cardinality does not track the
#: certificate count and it must never be index-paired.
X509_CA_FLAG = ("x509ce_x509ce_cA",)
X509_SAN_DNS = ("x509ce_x509ce_dNSName",)
X509_EXTENSION_ID = ("x509af_x509af_extension_id",)
#: Distinguished-name text. Cardinality varies with the number of RDN components, so
#: this is attributable to a specific certificate only when the chain holds exactly one.
X509_DN_TEXT = ("x509sat_x509sat_uTF8String", "x509sat_x509sat_printableString")

# Retained for backwards compatibility with any external reader of this module.
X509_SUBJECT_CN = X509_DN_TEXT
X509_SIG_ALGO = X509_ALGORITHM_ID

# ---- mail protocols -------------------------------------------------------
SMTP_REQ_COMMAND = ("smtp_smtp_req_command",)
SMTP_RSP_CODE = ("smtp_smtp_response_code",)
SMTP_RSP_PARAM = ("smtp_smtp_rsp_parameter",)
SMTP_COMMAND_LINE = ("smtp_smtp_command_line",)

IMAP_REQ_COMMAND = ("imap_imap_request_command",)
IMAP_RSP_STATUS = ("imap_imap_response_status",)
IMAP_LINE = ("imap_imap_line",)

# NOTE: tshark names the POP3 layer "pop" (not "pop3"). Verified 4.6.8.
POP_REQ_COMMAND = ("pop_pop_request_command",)
POP_RSP_INDICATOR = ("pop_pop_response_indicator",)
POP_RSP_DESCRIPTION = ("pop_pop_response_description",)

# Protocol tokens as they appear in frame.protocols, mapped to our canonical names.
PROTOCOL_TOKENS = {
    "smtp": "smtp",
    "imap": "imap",
    "pop": "pop3",      # canonicalise tshark's "pop" to "pop3"
    "tls": "tls",
}

# Well-known mail ports -> (protocol, implicit_tls). Used only as corroborating
# evidence when the payload is opaque (implicit TLS has no cleartext banner).
MAIL_PORTS = {
    25: ("smtp", False), 587: ("smtp", False), 465: ("smtp", True),
    143: ("imap", False), 993: ("imap", True),
    110: ("pop3", False), 995: ("pop3", True),
}
