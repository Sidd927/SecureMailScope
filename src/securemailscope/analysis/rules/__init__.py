"""Deterministic security rules, grouped by family."""
from securemailscope.analysis.rules.tls_rules import (
    DeprecatedTlsVersionRule, TlsHandshakeCompletionRule, CertificateObservabilityRule,
)
from securemailscope.analysis.rules.keyexchange_rules import (
    KeyExchangeRule, ForwardSecrecyRule,
)
from securemailscope.analysis.rules.certificate_rules import (
    CertificatePresenceRule, CertificateExpiryRule, CertificateKeyStrengthRule,
    CertificateSignatureRule, CertificateChainRule,
)
from securemailscope.analysis.rules.configuration_rules import InsecureConfigurationRule
from securemailscope.analysis.rules.starttls_rules import (
    StartTlsUpgradeRule, StartTlsAdvertisementRule, ImplicitTlsRule,
)
from securemailscope.analysis.rules.plaintext_rules import (
    CleartextAuthenticationRule, PlaintextSessionRule,
)

#: Registration order determines output order, so it is part of deterministic behaviour.
#: Phase-11 rules are appended after the existing eight rather than interleaved, so the
#: relative order of pre-existing findings is unchanged.
ALL_RULES = (
    DeprecatedTlsVersionRule, TlsHandshakeCompletionRule, CertificateObservabilityRule,
    StartTlsAdvertisementRule, StartTlsUpgradeRule, ImplicitTlsRule,
    CleartextAuthenticationRule, PlaintextSessionRule,
    # ---- Phase 11: D-09, D-17, D-10..D-14, D-16 ----
    KeyExchangeRule, ForwardSecrecyRule,
    CertificatePresenceRule, CertificateExpiryRule, CertificateKeyStrengthRule,
    CertificateSignatureRule, CertificateChainRule,
    InsecureConfigurationRule,
)

__all__ = [c.__name__ for c in ALL_RULES] + ["ALL_RULES"]
