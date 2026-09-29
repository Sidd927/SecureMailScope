"""
Remediation guidance (A-05, Phase 7).

Every template here is bound to one issue class and therefore to the rules that produce
it. There is no generic "follow security best practice" fallback, because advice that
does not name the observation it came from is noise an analyst has to verify from
scratch.

Four rules govern the wording:

* **Observed, not inferred.** The `observed` line restates what the capture showed, in
  the rule's own terms.
* **Action, not aspiration.** The action must be something a mail administrator can
  execute on the service that was captured.
* **Verification is mandatory.** Every template says how to confirm the fix, because
  this system cannot observe a configuration change — only a later capture can.
* **Never claim success.** Nothing here asserts that remediation worked; the engine has
  no evidence for that and says so in the limitations.

Text is authored in this repository. No string from a packet ever reaches an analyst
through this module.
"""
from __future__ import annotations

from typing import Dict, Optional, Sequence, Tuple

from securemailscope.posture.model import (
    IssueClass, RemediationGuidance, StandardCitation,
)

#: Carried on every template: the engine sees traffic, not configuration.
_UNIVERSAL_LIMITS: Tuple[str, ...] = (
    "this recommendation addresses what the capture showed; the service may have other "
    "configuration that was not exercised by the captured traffic",
    "SecureMailScope cannot confirm that a change was applied or effective -- only a "
    "later capture can",
)

_TEMPLATES: Dict[IssueClass, Dict[str, str]] = {
    IssueClass.DEPRECATED_TLS_VERSION: {
        "observed": "The server negotiated a TLS version that current standards "
                    "prohibit or deprecate.",
        "why": "RFC 8996 states TLS 1.0 and TLS 1.1 MUST NOT be used, and NIST SP "
               "800-52r2 SS3.1 states servers shall not be configured to use TLS 1.0 or "
               "earlier. These versions depend on weakened constructions and are not "
               "acceptable for protecting mail credentials or content.",
        "action": "Disable the deprecated protocol versions on the mail service and "
                  "require TLS 1.2 as a minimum, preferring TLS 1.3. Check both the "
                  "submission/access listeners and any MTA-to-MTA configuration.",
        "verify": "Re-capture traffic to this service after the change and confirm the "
                  "negotiated version reported in the ServerHello is TLS 1.2 or TLS 1.3.",
    },
    IssueClass.PLAINTEXT_AUTH_EXPOSURE: {
        "observed": "Authentication activity was observed on a session where no TLS "
                    "was established.",
        "why": "Credentials sent without TLS are readable by anyone on the path. RFC "
               "8314 declares cleartext submission and access obsolete, and NIST SP "
               "800-52r2 SS3.1 requires TLS to protect transmitted data.",
        "action": "Require TLS before authentication: enable implicit TLS on the "
                  "dedicated ports (465/993/995) or enforce STARTTLS/STLS, and reject "
                  "authentication attempts on unprotected connections.",
        "verify": "Re-capture and confirm that no authentication command appears before "
                  "a completed TLS handshake on any session to this service.",
    },
    IssueClass.NO_TLS_PROTECTION: {
        "observed": "A mail session completed without any TLS protection.",
        "why": "The entire session, including message content and any credentials, was "
               "carried in cleartext. RFC 8314 declares this obsolete for submission "
               "and access.",
        "action": "Require TLS for this service, preferring implicit TLS on the "
                  "dedicated port, or enforce STARTTLS/STLS for the cleartext port.",
        "verify": "Re-capture and confirm TLS records are present on every session to "
                  "this service.",
    },
    IssueClass.STARTTLS_UPGRADE_FAILURE: {
        "observed": "A STARTTLS/STLS upgrade was requested but the session was not "
                    "subsequently protected by TLS.",
        "why": "An upgrade that is requested and not completed leaves the session in "
               "cleartext while both parties expected protection. RFC 3207 SS6 requires "
               "that a failed upgrade not be silently treated as acceptable.",
        "action": "Ensure the service both offers and accepts STARTTLS/STLS and that "
                  "its certificate and TLS configuration permit the handshake to "
                  "complete. Configure clients to fail closed when an upgrade does not "
                  "succeed rather than continuing in cleartext.",
        "verify": "Re-capture and confirm that every session issuing STARTTLS/STLS "
                  "reaches an established TLS state.",
    },
    IssueClass.STARTTLS_BEHAVIOUR_DEVIATION: {
        "observed": "This session's STARTTLS/STLS behaviour differs from the behaviour "
                    "established by prior comparable sessions to the same endpoint.",
        "why": "A behavioural difference is not by itself a vulnerability, but an "
               "endpoint that usually upgrades and on this occasion did not is worth an "
               "analyst's attention. RFC 3207 SS6 documents that the capability can be "
               "removed in transit, which is one of several explanations.",
        "action": "Investigate why this session differed: compare the client and server "
                  "configuration against the sessions that formed the baseline, and "
                  "check for an intermediary on this path. Do not treat the deviation "
                  "as confirmation of manipulation.",
        "verify": "Capture further sessions from the same client to the same endpoint "
                  "and determine whether the behaviour is persistent or isolated.",
    },
    IssueClass.TLS_VERSION_DEVIATION: {
        "observed": "The negotiated TLS version differs from the version established by "
                    "prior comparable sessions to the same endpoint.",
        "why": "A downward change in negotiated version can indicate a configuration "
               "regression or a path that constrains the handshake. NIST SP 800-52r2 "
               "SS3.1 defines which versions are acceptable.",
        "action": "Compare the service's current TLS configuration against the version "
                  "seen in the baseline sessions, and confirm no intermediary is "
                  "constraining the negotiation.",
        "verify": "Re-capture and confirm the negotiated version is stable and meets "
                  "the required minimum.",
    },
}


def guidance_for(issue_class: IssueClass,
                 citations: Sequence[StandardCitation],
                 affected_scope: str,
                 rule_remediation: Optional[str] = None,
                 extra_limitations: Sequence[str] = ()) -> Optional[RemediationGuidance]:
    """Build remediation for one issue class, or None if no template applies.

    Returning None is deliberate: an issue class with no authored template gets no
    advice rather than generic filler. `rule_remediation` — the string the Phase-4 rule
    itself emitted — is appended when present, so the rule's own wording is preserved
    alongside the structured guidance rather than replaced by it.
    """
    template = _TEMPLATES.get(issue_class)
    if template is None:
        return None
    action = template["action"]
    if rule_remediation and rule_remediation.strip():
        action = f"{action} Rule guidance: {rule_remediation.strip()}"
    return RemediationGuidance(
        observed=template["observed"],
        why_it_matters=template["why"],
        recommended_action=action,
        affected_scope=affected_scope,
        verification=template["verify"],
        citations=tuple(citations),
        limitations=_UNIVERSAL_LIMITS + tuple(extra_limitations),
    )


def has_template(issue_class: IssueClass) -> bool:
    return issue_class in _TEMPLATES


#: Issue classes that are observations rather than actionable problems. Listed
#: explicitly so "no remediation" is a recorded decision rather than an oversight.
NON_ACTIONABLE: Tuple[IssueClass, ...] = (
    IssueClass.CERTIFICATE_OBSERVABILITY,   # a limit of passive capture, not a defect
    IssueClass.IMPLICIT_TLS_SESSION,        # a good state
    IssueClass.TLS_HANDSHAKE_EVIDENCE,      # an evidence statement
    IssueClass.STARTTLS_ADVERTISEMENT,      # informational unless it fails
    IssueClass.ANOMALY,                     # a prioritisation signal, not a finding
    IssueClass.UNCLASSIFIED,
)
