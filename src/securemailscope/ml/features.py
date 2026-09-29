"""
ML feature layer (Phase-6 §6-§9).

This module answers one question: *what can a model legitimately look at?*

Three rules govern everything here and are enforced by tests:

1. **No deterministic-label leakage.** The extractor accepts `SessionEvidence` and
   Phase-5 *derived context* (comparability, baseline, contrast) only. It never sees a
   `SecurityFinding` or a `CrossSessionFinding`, never imports the rule modules, and
   never encodes a rule id, severity, finding status or risk score. A model that is fed
   the rules' own answers has learned nothing (docs/research/01D §6 -- the trap three
   audited competitors fell into).

2. **Missingness is not zero.** `NOT_OBSERVABLE` ("TLS 1.3 encrypts the certificate")
   and `UNKNOWN` ("we did not capture it") and `false` ("it was absent") are three
   different facts. Categorical features therefore carry the evidence *state* as its own
   category rather than collapsing it; numeric features carry an explicit
   `<name>__missing` indicator beside a documented neutral fill.

3. **Encoding must not invent order.** Categorical values are one-hot encoded against a
   declared vocabulary, so `TLS1.2 = 1, TLS1.3 = 2` never implies a magnitude. The one
   deliberate exception is `tls_version_ordinal`, where the ordering is a real property
   of the protocol and the justification is recorded on the spec itself.

Extraction (evidence -> named logical values) is deliberately separate from encoding
(named values -> a stable numeric matrix). Only the first needs to understand evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

from securemailscope.crosssession.baseline import Baseline, BaselineStatus
from securemailscope.crosssession.comparability import (
    Comparability, ComparabilityAssessment,
)
from securemailscope.crosssession.contrast import ContrastResult, ContrastState
from securemailscope.evidence.states import EvidenceField, EvidenceState
from securemailscope.session.model import (
    AppState, Completeness, Direction, SessionEvidence, TlsState, TransportRole,
)

#: Bump on ANY change to the feature set, vocabulary or encoding. A model artifact
#: records the schema version it was trained against and refuses to score a mismatch.
FEATURE_SCHEMA_VERSION = "1.0"

#: Sentinel category for a value outside the declared vocabulary. Unknown categoricals
#: must land somewhere explicit rather than silently vanishing or shifting columns.
OTHER = "__other__"
NONE_CAT = "__none__"

#: Neutral fill for a missing numeric. Always paired with a `__missing` indicator, so
#: the model can learn "this was absent" instead of "this was zero".
MISSING_FILL = 0.0


class FeatureKind(str, Enum):
    NUMERIC = "NUMERIC"
    BINARY = "BINARY"
    CATEGORICAL = "CATEGORICAL"


class FeatureGroup(str, Enum):
    """Ablation units (Phase-6 §31). Each group can be switched off independently."""
    PROTOCOL = "PROTOCOL"
    TLS = "TLS"
    STRUCTURE = "STRUCTURE"
    AUTH = "AUTH"
    CONTEXT = "CONTEXT"          # cross-session deviation


class LeakageRisk(str, Enum):
    """How likely this feature is to smuggle in a deterministic answer or a generator
    artifact rather than security behaviour. Drives the §31 ablation and the §32 test."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"                # never shipped; present only to be tested and rejected


@dataclass(frozen=True)
class FeatureSpec:
    """Governance record for one logical feature (Phase-6 §7)."""
    feature_id: str
    group: FeatureGroup
    kind: FeatureKind
    source: str
    meaning: str
    leakage_risk: LeakageRisk
    missing_policy: str
    vocabulary: Tuple[str, ...] = ()
    ordinal_justification: str = ""

    def __post_init__(self) -> None:
        if self.kind is FeatureKind.CATEGORICAL and not self.vocabulary:
            raise ValueError(f"{self.feature_id}: categorical needs a declared vocabulary")
        if self.kind is not FeatureKind.CATEGORICAL and self.vocabulary:
            raise ValueError(f"{self.feature_id}: only categoricals carry a vocabulary")

    def to_dict(self) -> dict:
        return {"feature_id": self.feature_id, "group": self.group.value,
                "kind": self.kind.value, "source": self.source, "meaning": self.meaning,
                "leakage_risk": self.leakage_risk.value,
                "missing_policy": self.missing_policy,
                "vocabulary": list(self.vocabulary),
                "ordinal_justification": self.ordinal_justification}


# --------------------------------------------------------------- vocabularies
#: Evidence-state categories shared by every tri-state field. `true`/`false` are the two
#: decided outcomes; the rest are the evidence model's own states, kept distinct because
#: they mean genuinely different things (docs/architecture/04 §1).
_TRI = ("true", "false", EvidenceState.UNKNOWN.value, EvidenceState.AMBIGUOUS.value,
        EvidenceState.INCOMPLETE.value, EvidenceState.NOT_OBSERVABLE.value,
        EvidenceState.INFERRED.value, OTHER)

_PROTO = ("smtp", "imap", "pop3", NONE_CAT, OTHER)
_TLS_MODE = ("explicit", "implicit")
_APP_STATE = tuple(s.value for s in AppState) + (OTHER,)
_TLS_STATE = tuple(s.value for s in TlsState) + (OTHER,)
_COMPLETENESS = tuple(c.value for c in Completeness) + (OTHER,)
_COMPARABILITY = tuple(c.value for c in Comparability) + (OTHER,)
_BASELINE_STATUS = tuple(b.value for b in BaselineStatus) + (OTHER,)
_CONTRAST_STATE = tuple(c.value for c in ContrastState) + (OTHER,)
_TLS_VERSION = ("SSL3.0", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3",
                EvidenceState.UNKNOWN.value, EvidenceState.AMBIGUOUS.value,
                EvidenceState.INCOMPLETE.value, EvidenceState.NOT_OBSERVABLE.value, OTHER)
_PORT_CLASS = ("smtp", "submission", "smtps", "imap", "imaps", "pop3", "pop3s", OTHER)

#: Ordinal scale for TLS versions. Unlike most categoricals this ordering is real:
#: versions are chronological and RFC 8996 / NIST SP 800-52r2 deprecate monotonically
#: from the bottom. Declared explicitly so the justification travels with the feature.
_VERSION_ORDINAL = {"SSL3.0": 1.0, "TLS1.0": 2.0, "TLS1.1": 3.0,
                    "TLS1.2": 4.0, "TLS1.3": 5.0}

#: Cipher suites are kept as an opaque categorical with a small declared vocabulary.
#: High cardinality plus generator-specific suite lists make this the single most
#: artifact-prone feature in the set, so it is MEDIUM risk and gets ablated (§31).
_CIPHER = ("0x1301", "0x1302", "0x1303", "0xc02f", "0xc030", "0xc013", "0x009c",
           EvidenceState.UNKNOWN.value, EvidenceState.NOT_OBSERVABLE.value,
           EvidenceState.AMBIGUOUS.value, EvidenceState.INCOMPLETE.value, OTHER)


# ------------------------------------------------------------------- the specs
def _spec(fid, group, kind, source, meaning, risk, missing, vocab=(), ordinal="") -> FeatureSpec:
    return FeatureSpec(fid, group, kind, source, meaning, risk, missing, tuple(vocab), ordinal)


FEATURE_SPECS: Tuple[FeatureSpec, ...] = (
    # ---- PROTOCOL -----------------------------------------------------------
    _spec("proto", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.protocol", "mail protocol identified for the stream",
          LeakageRisk.LOW, "unidentified protocol becomes __none__", _PROTO),
    _spec("tls_mode", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.implicit_tls", "implicit vs explicit (upgrade) TLS mode",
          LeakageRisk.NONE, "always decidable; structural boolean", _TLS_MODE),
    _spec("port_class", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.server_port", "IANA service class of the server port",
          LeakageRisk.MEDIUM, "unrecognised port becomes __other__", _PORT_CLASS),
    _spec("starttls_advertised", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.starttls_advertised",
          "capability advertisement state; AMBIGUOUS is its own category because "
          "stripped and unsupported are byte-identical (02B §3.1)",
          LeakageRisk.LOW, "evidence state carried as a category", _TRI),
    _spec("starttls_requested", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.starttls_requested", "client issued STARTTLS/STLS",
          LeakageRisk.LOW, "evidence state carried as a category", _TRI),
    _spec("starttls_accepted", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.starttls_accepted", "server accepted the upgrade request",
          LeakageRisk.LOW, "evidence state carried as a category", _TRI),
    _spec("plaintext_continuation", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.plaintext_continuation", "cleartext dialogue continued",
          LeakageRisk.LOW, "evidence state carried as a category", _TRI),
    _spec("app_state", FeatureGroup.PROTOCOL, FeatureKind.CATEGORICAL,
          "SessionEvidence.app_state", "terminal application dialogue state",
          LeakageRisk.LOW, "unmapped state becomes __other__", _APP_STATE),
    _spec("n_transitions", FeatureGroup.PROTOCOL, FeatureKind.NUMERIC,
          "len(SessionEvidence.transitions)", "number of recorded state transitions",
          LeakageRisk.LOW, "always present; 0 is a real count"),
    _spec("n_events", FeatureGroup.PROTOCOL, FeatureKind.NUMERIC,
          "len(SessionEvidence.events)", "number of observed protocol events",
          LeakageRisk.LOW, "always present; 0 is a real count"),
    _spec("n_event_kinds", FeatureGroup.PROTOCOL, FeatureKind.NUMERIC,
          "SessionEvidence.events", "distinct event kinds observed",
          LeakageRisk.LOW, "always present; 0 is a real count"),
    _spec("has_greeting", FeatureGroup.PROTOCOL, FeatureKind.BINARY,
          "SessionEvidence.events", "a server greeting was observed",
          LeakageRisk.LOW, "absence is a real observation, encoded 0"),
    _spec("has_capability", FeatureGroup.PROTOCOL, FeatureKind.BINARY,
          "SessionEvidence.events", "a capability response was observed",
          LeakageRisk.LOW, "absence is a real observation, encoded 0"),

    # ---- TLS ----------------------------------------------------------------
    _spec("tls_state", FeatureGroup.TLS, FeatureKind.CATEGORICAL,
          "SessionEvidence.tls_state", "how far the handshake demonstrably progressed",
          LeakageRisk.LOW, "unmapped state becomes __other__", _TLS_STATE),
    _spec("tls_version", FeatureGroup.TLS, FeatureKind.CATEGORICAL,
          "SessionEvidence.tls_negotiated_version",
          "negotiated version from the ServerHello (supported_versions for 1.3)",
          LeakageRisk.LOW, "evidence state carried as a category", _TLS_VERSION),
    _spec("tls_version_ordinal", FeatureGroup.TLS, FeatureKind.NUMERIC,
          "SessionEvidence.tls_negotiated_version",
          "ordinal position of the negotiated version",
          LeakageRisk.LOW, "missing -> neutral fill + tls_version_ordinal__missing=1",
          (), "TLS versions are chronologically ordered and RFC 8996 / NIST SP 800-52r2 "
              "deprecate monotonically from the oldest, so magnitude is meaningful here "
              "in a way it is not for protocol names or cipher identifiers"),
    _spec("tls_cipher", FeatureGroup.TLS, FeatureKind.CATEGORICAL,
          "SessionEvidence.tls_cipher_suite", "negotiated cipher suite identifier",
          LeakageRisk.MEDIUM,
          "evidence state carried as a category; unseen suite becomes __other__", _CIPHER),
    _spec("tls_transition", FeatureGroup.TLS, FeatureKind.CATEGORICAL,
          "SessionEvidence.tls_transition", "whether a cleartext->TLS transition occurred",
          LeakageRisk.LOW, "evidence state carried as a category", _TRI),
    _spec("tls_records_present", FeatureGroup.TLS, FeatureKind.BINARY,
          "SessionEvidence.tls_state", "any TLS record observed in the stream",
          LeakageRisk.LOW, "absence is a real observation, encoded 0"),

    # ---- STRUCTURE ----------------------------------------------------------
    _spec("packet_count_log", FeatureGroup.STRUCTURE, FeatureKind.NUMERIC,
          "SessionEvidence.packet_count", "log1p packet count",
          LeakageRisk.MEDIUM, "always present; 0 is a real count"),
    _spec("duration_s", FeatureGroup.STRUCTURE, FeatureKind.NUMERIC,
          "SessionEvidence.start_epoch/end_epoch", "wall duration of the session",
          LeakageRisk.MEDIUM,
          "missing timestamps -> neutral fill + duration_s__missing=1"),
    _spec("frame_span", FeatureGroup.STRUCTURE, FeatureKind.NUMERIC,
          "SessionEvidence.first_frame/last_frame", "frame-number span of the session",
          LeakageRisk.MEDIUM, "missing frames -> neutral fill + frame_span__missing=1"),
    _spec("completeness", FeatureGroup.STRUCTURE, FeatureKind.CATEGORICAL,
          "SessionEvidence.completeness", "whether the capture shows the whole session",
          LeakageRisk.LOW, "unmapped value becomes __other__", _COMPLETENESS),
    _spec("setup_observed", FeatureGroup.STRUCTURE, FeatureKind.BINARY,
          "SessionEvidence.transport_flags", "TCP setup observed", LeakageRisk.LOW,
          "absence is a real observation, encoded 0"),
    _spec("teardown_observed", FeatureGroup.STRUCTURE, FeatureKind.BINARY,
          "SessionEvidence.transport_flags", "TCP teardown observed", LeakageRisk.LOW,
          "absence is a real observation, encoded 0"),
    _spec("reset_observed", FeatureGroup.STRUCTURE, FeatureKind.BINARY,
          "SessionEvidence.transport_flags", "TCP reset observed", LeakageRisk.LOW,
          "absence is a real observation, encoded 0"),
    _spec("events_per_packet", FeatureGroup.STRUCTURE, FeatureKind.NUMERIC,
          "SessionEvidence", "application events per captured packet",
          LeakageRisk.MEDIUM, "zero packets -> neutral fill + events_per_packet__missing=1"),
    _spec("c2s_events", FeatureGroup.STRUCTURE, FeatureKind.NUMERIC,
          "SessionEvidence.events", "client-to-server events", LeakageRisk.LOW,
          "always present; 0 is a real count"),
    _spec("s2c_events", FeatureGroup.STRUCTURE, FeatureKind.NUMERIC,
          "SessionEvidence.events", "server-to-client events", LeakageRisk.LOW,
          "always present; 0 is a real count"),
    _spec("direction_balance", FeatureGroup.STRUCTURE, FeatureKind.NUMERIC,
          "SessionEvidence.events", "(c2s - s2c) / (c2s + s2c)", LeakageRisk.LOW,
          "no directional events -> neutral fill + direction_balance__missing=1"),

    # ---- AUTH ---------------------------------------------------------------
    _spec("auth_activity", FeatureGroup.AUTH, FeatureKind.CATEGORICAL,
          "SessionEvidence.auth_activity", "authentication commands observed",
          LeakageRisk.LOW, "evidence state carried as a category", _TRI),
    _spec("auth_before_tls", FeatureGroup.AUTH, FeatureKind.BINARY,
          "SessionEvidence.events + tls frames",
          "authentication seen before any TLS record in this stream",
          LeakageRisk.LOW, "no auth or no TLS -> 0, meaning 'not observed in that order'"),
    _spec("auth_without_tls", FeatureGroup.AUTH, FeatureKind.BINARY,
          "SessionEvidence", "authentication observed while no TLS was ever established",
          LeakageRisk.MEDIUM, "absence is a real observation, encoded 0"),

    # ---- CONTEXT (cross-session deviation) ----------------------------------
    _spec("comparability", FeatureGroup.CONTEXT, FeatureKind.CATEGORICAL,
          "ComparabilityAssessment.result",
          "whether this session may participate in cross-session reasoning at all",
          LeakageRisk.LOW, "no context supplied -> __other__", _COMPARABILITY),
    _spec("baseline_status", FeatureGroup.CONTEXT, FeatureKind.CATEGORICAL,
          "Baseline.status", "whether a prior-history baseline could be established",
          LeakageRisk.LOW, "no context supplied -> __other__", _BASELINE_STATUS),
    _spec("baseline_size", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "Baseline.sample_count", "number of prior comparable sessions",
          LeakageRisk.LOW, "no baseline -> neutral fill + baseline_size__missing=1"),
    _spec("baseline_upgrade_rate", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "Baseline.features['tls_established']",
          "fraction of prior comparable sessions that established TLS",
          LeakageRisk.LOW,
          "no usable baseline -> neutral fill + baseline_upgrade_rate__missing=1"),
    _spec("upgrade_deviation", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "Baseline + SessionEvidence.tls_state",
          "|this session upgraded - baseline upgrade rate|: the measured deviation, "
          "not a verdict about it",
          LeakageRisk.LOW, "no usable baseline -> neutral fill + upgrade_deviation__missing=1"),
    _spec("baseline_consistency", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "Baseline.features", "fraction of baselined features whose history agreed",
          LeakageRisk.LOW, "no usable baseline -> neutral fill + baseline_consistency__missing=1"),
    _spec("deviating_features", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "Baseline.features + SessionEvidence",
          "count of baselined features where this session differs from the dominant value",
          LeakageRisk.LOW, "no usable baseline -> neutral fill + deviating_features__missing=1"),
    _spec("contrast_state", FeatureGroup.CONTEXT, FeatureKind.CATEGORICAL,
          "ContrastResult.state",
          "availability of an unaffected control endpoint; describes what evidence "
          "exists, not whether the session is malicious",
          LeakageRisk.MEDIUM, "no context supplied -> __other__", _CONTRAST_STATE),
    _spec("control_count", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "ContrastResult.control_sessions", "number of control sessions located",
          LeakageRisk.LOW, "no context -> neutral fill + control_count__missing=1"),
    _spec("control_upgrade_rate", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "ContrastResult.control_upgrade_rate",
          "fraction of control sessions that established TLS", LeakageRisk.LOW,
          "no contrast -> neutral fill + control_upgrade_rate__missing=1"),
    _spec("contrast_gap", FeatureGroup.CONTEXT, FeatureKind.NUMERIC,
          "ContrastResult + SessionEvidence.tls_state",
          "control upgrade rate minus this session's upgrade outcome",
          LeakageRisk.LOW, "no contrast -> neutral fill + contrast_gap__missing=1"),
)

SPEC_BY_ID: Dict[str, FeatureSpec] = {s.feature_id: s for s in FEATURE_SPECS}

#: Fields the extractor is forbidden to read. Identity and provenance belong in the
#: evidence record, never in the learned vector: an IP or capture id lets a model
#: memorise a scenario, and a rule output lets it memorise the rules (§5, §20, §32).
FORBIDDEN_INPUTS: Tuple[str, ...] = (
    "capture_id", "stream_key", "tcp_stream_id", "client_ip", "server_ip",
    "client_port", "first_frame", "last_frame", "start_epoch", "end_epoch",
    "endpoint_basis", "notes", "rule_id", "severity", "finding_status",
    "standards", "remediation", "risk_score", "posture_score", "scenario", "generator",
    "ground_truth", "label",
)


@dataclass(frozen=True)
class CrossSessionContext:
    """Phase-5 *derived context* for one session.

    Deliberately NOT a `CrossSessionFinding`. Baselines and contrast results describe
    measured behaviour and evidence availability; findings are conclusions. Only the
    former may reach the model (§5, §29).
    """
    comparability: Optional[ComparabilityAssessment] = None
    baseline: Optional[Baseline] = None
    contrast: Optional[ContrastResult] = None

    @property
    def empty(self) -> bool:
        return (self.comparability is None and self.baseline is None
                and self.contrast is None)


@dataclass(frozen=True)
class MLFeatureVector:
    """Versioned model input contract (Phase-6 §26).

    Holds *logical* named values, not a raw array. Encoding to a numeric matrix is a
    separate, explicit step so that the contract survives changes of encoding.
    """
    schema_version: str
    session_key: Optional[str]
    capture_id: str
    values: Dict[str, object]
    missing: Tuple[str, ...] = ()
    context_available: bool = False

    def to_dict(self) -> dict:
        return {"schema_version": self.schema_version, "session_key": self.session_key,
                "capture_id": self.capture_id,
                "values": {k: self.values[k] for k in sorted(self.values)},
                "missing": list(self.missing),
                "context_available": self.context_available}


# ------------------------------------------------------------------ extraction
#: States in which a carried value is an actual finding rather than a placeholder.
_DECIDED = (EvidenceState.OBSERVED, EvidenceState.INFERRED)


def _decided_true(f: EvidenceField) -> bool:
    return f.state in _DECIDED and f.value is True


def _tri(f: EvidenceField) -> str:
    """Tri-state read that preserves the evidence state rather than collapsing it.

    **The state wins over the value, and that ordering is the whole point.** Phase 3
    records an absent STARTTLS advertisement as `EvidenceField.ambiguous(False, ...)`:
    it carries the value `False` *and* the state AMBIGUOUS, because stripping and
    genuine non-support are byte-identical (02B §3.1). Reading the value first would
    hand the model a confident `false` for the single most important undecided fact in
    the system. Only OBSERVED and INFERRED values are reported as decided; every other
    state reports itself.
    """
    if f.state in _DECIDED:
        if f.value is True:
            return "true"
        if f.value is False:
            return "false"
    return f.state.value


def _port_class(port: Optional[int]) -> str:
    return {25: "smtp", 587: "submission", 465: "smtps", 143: "imap", 993: "imaps",
            110: "pop3", 995: "pop3s"}.get(port or -1, OTHER)


def _version_category(f: EvidenceField) -> str:
    if f.value is None:
        return f.state.value
    return str(f.value)


def _cipher_category(f: EvidenceField) -> str:
    if f.value is None:
        return f.state.value
    return str(f.value).lower()


def _upgraded(session: SessionEvidence) -> bool:
    return session.tls_state is TlsState.ESTABLISHED


class MLFeatureExtractor:
    """`SessionEvidence` (+ optional Phase-5 context) -> `MLFeatureVector`.

    Pure and deterministic: no I/O, no clock, no randomness, no PCAP re-parsing. The
    same session and context always produce the same vector.
    """

    schema_version = FEATURE_SCHEMA_VERSION

    def __init__(self, groups: Optional[Sequence[FeatureGroup]] = None) -> None:
        #: Restricting groups is how §31 ablation is run -- the encoder then emits
        #: fewer columns, rather than the extractor emitting silent zeros.
        self.groups: Tuple[FeatureGroup, ...] = tuple(groups) if groups else tuple(FeatureGroup)

    @property
    def specs(self) -> Tuple[FeatureSpec, ...]:
        return tuple(s for s in FEATURE_SPECS if s.group in self.groups)

    def extract(self, session: SessionEvidence,
                context: Optional[CrossSessionContext] = None) -> MLFeatureVector:
        ctx = context or CrossSessionContext()
        values: Dict[str, object] = {}
        missing: List[str] = []

        def num(fid: str, value: Optional[float]) -> None:
            if value is None:
                values[fid] = MISSING_FILL
                missing.append(fid)
            else:
                values[fid] = float(value)

        active = {g for g in self.groups}

        if FeatureGroup.PROTOCOL in active:
            self._protocol(session, values, num)
        if FeatureGroup.TLS in active:
            self._tls(session, values, num)
        if FeatureGroup.STRUCTURE in active:
            self._structure(session, values, num)
        if FeatureGroup.AUTH in active:
            self._auth(session, values)
        if FeatureGroup.CONTEXT in active:
            self._context(session, ctx, values, num)

        return MLFeatureVector(
            schema_version=self.schema_version,
            session_key=session.stream_key,
            capture_id=session.capture_id,
            values=values,
            missing=tuple(sorted(missing)),
            context_available=not ctx.empty,
        )

    # ---- group extractors ---------------------------------------------------
    def _protocol(self, s: SessionEvidence, v: Dict[str, object], num) -> None:
        kinds = [e.kind for e in s.events]
        v["proto"] = s.protocol if s.protocol else NONE_CAT
        v["tls_mode"] = "implicit" if s.implicit_tls else "explicit"
        v["port_class"] = _port_class(s.server_port)
        v["starttls_advertised"] = _tri(s.starttls_advertised)
        v["starttls_requested"] = _tri(s.starttls_requested)
        v["starttls_accepted"] = _tri(s.starttls_accepted)
        v["plaintext_continuation"] = _tri(s.plaintext_continuation)
        v["app_state"] = s.app_state.value
        num("n_transitions", len(s.transitions))
        num("n_events", len(s.events))
        num("n_event_kinds", len(set(kinds)))
        v["has_greeting"] = 1.0 if any("greeting" in k for k in kinds) else 0.0
        v["has_capability"] = 1.0 if any("capabilit" in k for k in kinds) else 0.0

    def _tls(self, s: SessionEvidence, v: Dict[str, object], num) -> None:
        v["tls_state"] = s.tls_state.value
        version = _version_category(s.tls_negotiated_version)
        v["tls_version"] = version
        # Ordinal only when a version was actually decided; otherwise missing, never 0.
        num("tls_version_ordinal", _VERSION_ORDINAL.get(version))
        v["tls_cipher"] = _cipher_category(s.tls_cipher_suite)
        v["tls_transition"] = _tri(s.tls_transition)
        v["tls_records_present"] = 0.0 if s.tls_state is TlsState.NONE else 1.0

    def _structure(self, s: SessionEvidence, v: Dict[str, object], num) -> None:
        import math
        num("packet_count_log", math.log1p(max(0, s.packet_count)))
        duration = (s.end_epoch - s.start_epoch
                    if s.start_epoch is not None and s.end_epoch is not None else None)
        num("duration_s", duration)
        span = (s.last_frame - s.first_frame
                if s.first_frame is not None and s.last_frame is not None else None)
        num("frame_span", span)
        v["completeness"] = s.completeness.value
        flags = set(s.transport_flags)
        v["setup_observed"] = 1.0 if TransportRole.SETUP_OBSERVED in flags else 0.0
        v["teardown_observed"] = 1.0 if TransportRole.TEARDOWN_OBSERVED in flags else 0.0
        v["reset_observed"] = 1.0 if TransportRole.RESET_OBSERVED in flags else 0.0
        num("events_per_packet",
            len(s.events) / s.packet_count if s.packet_count else None)
        c2s = sum(1 for e in s.events if e.direction is Direction.CLIENT_TO_SERVER)
        s2c = sum(1 for e in s.events if e.direction is Direction.SERVER_TO_CLIENT)
        num("c2s_events", c2s)
        num("s2c_events", s2c)
        num("direction_balance", (c2s - s2c) / (c2s + s2c) if (c2s + s2c) else None)

    def _auth(self, s: SessionEvidence, v: Dict[str, object]) -> None:
        v["auth_activity"] = _tri(s.auth_activity)
        auth_frames = [e.frame_number for e in s.events
                       if "auth" in e.kind.lower() and e.frame_number is not None]
        tls_frames = [fr for t in s.transitions
                      if t.to_state in (AppState.TLS_NEGOTIATING, AppState.TLS_ESTABLISHED)
                      for fr in t.evidence_frames]
        v["auth_before_tls"] = (
            1.0 if auth_frames and tls_frames and min(auth_frames) < min(tls_frames) else 0.0)
        v["auth_without_tls"] = (
            1.0 if _decided_true(s.auth_activity) and not _upgraded(s) else 0.0)

    def _context(self, s: SessionEvidence, ctx: CrossSessionContext,
                 v: Dict[str, object], num) -> None:
        v["comparability"] = ctx.comparability.result.value if ctx.comparability else OTHER
        baseline = ctx.baseline
        v["baseline_status"] = baseline.status.value if baseline else OTHER
        num("baseline_size", baseline.sample_count if baseline else None)

        usable = baseline is not None and baseline.usable
        upgrade_rate = None
        if usable:
            summary = baseline.feature("tls_established")
            if summary is not None and summary.total:
                upgrade_rate = summary.rate("true")
        num("baseline_upgrade_rate", upgrade_rate)
        num("upgrade_deviation",
            abs((1.0 if _upgraded(s) else 0.0) - upgrade_rate) if upgrade_rate is not None
            else None)

        if usable and baseline.features:
            consistent = sum(1 for f in baseline.features.values() if f.is_consistent)
            num("baseline_consistency", consistent / len(baseline.features))
            subject = _subject_feature_values(s)
            deviating = sum(
                1 for name, summary in baseline.features.items()
                if summary.dominant is not None and subject.get(name) != summary.dominant)
            num("deviating_features", deviating)
        else:
            num("baseline_consistency", None)
            num("deviating_features", None)

        contrast = ctx.contrast
        v["contrast_state"] = contrast.state.value if contrast else OTHER
        num("control_count", len(contrast.control_sessions) if contrast else None)
        rate = contrast.control_upgrade_rate if contrast else None
        num("control_upgrade_rate", rate)
        num("contrast_gap",
            rate - (1.0 if _upgraded(s) else 0.0) if rate is not None else None)


def _subject_feature_values(session: SessionEvidence) -> Dict[str, str]:
    """Subject values in the SAME vocabulary the Phase-5 baseline summarises.

    Mirrors `crosssession.baseline._feature_values` so `deviating_features` compares
    like with like. Kept local rather than imported to avoid coupling the ML layer to a
    private helper whose meaning could drift.

    Note this deliberately uses Phase 5's value-first reading, NOT `_tri`'s state-first
    one. The comparison is against a Phase-5 baseline summary, so it has to speak that
    summary's vocabulary; using a different convention here would silently compare a
    subject against a differently-encoded history.
    """
    def state_of(f: EvidenceField) -> str:
        if f.value is True:
            return "true"
        if f.value is False:
            return "false"
        return f.state.value

    return {
        "starttls_advertised": state_of(session.starttls_advertised),
        "starttls_requested": state_of(session.starttls_requested),
        "tls_established": ("true" if session.tls_state is TlsState.ESTABLISHED
                            else session.tls_state.value),
        "tls_version": (str(session.tls_negotiated_version.value)
                        if session.tls_negotiated_version.value is not None
                        else session.tls_negotiated_version.state.value),
        "auth_activity": state_of(session.auth_activity),
    }
