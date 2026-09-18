"""Deterministic security rules, grouped by family."""
from securemailscope.analysis.rules.tls_rules import (
    DeprecatedTlsVersionRule, TlsHandshakeCompletionRule, CertificateObservabilityRule,
)
from securemailscope.analysis.rules.starttls_rules import (
    StartTlsUpgradeRule, StartTlsAdvertisementRule, ImplicitTlsRule,
)
from securemailscope.analysis.rules.plaintext_rules import (
    CleartextAuthenticationRule, PlaintextSessionRule,
)

#: Registration order determines output order, so it is part of deterministic behaviour.
ALL_RULES = (
    DeprecatedTlsVersionRule, TlsHandshakeCompletionRule, CertificateObservabilityRule,
    StartTlsAdvertisementRule, StartTlsUpgradeRule, ImplicitTlsRule,
    CleartextAuthenticationRule, PlaintextSessionRule,
)

__all__ = [c.__name__ for c in ALL_RULES] + ["ALL_RULES"]
