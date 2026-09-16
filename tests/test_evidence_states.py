"""Phase-1 evidence-model tests: the correctness contract (docs/architecture/04)."""
import pytest

from securemailscope.evidence import EvidenceField, EvidenceState, Provenance


def test_observed_requires_value():
    with pytest.raises(ValueError):
        EvidenceField.observed(None, "no value")


def test_valueless_states_reject_value():
    for ctor in (EvidenceState.UNKNOWN, EvidenceState.INCOMPLETE, EvidenceState.NOT_OBSERVABLE):
        with pytest.raises(ValueError):
            EvidenceField(value=True, state=ctor, basis="x")


def test_inferred_requires_basis():
    with pytest.raises(ValueError):
        EvidenceField(value=True, state=EvidenceState.INFERRED, basis="")


def test_factory_constructors_set_state():
    assert EvidenceField.observed("TLSv1.3", "sh").state == EvidenceState.OBSERVED
    assert EvidenceField.inferred(True, "client sent STARTTLS").state == EvidenceState.INFERRED
    assert EvidenceField.ambiguous(False, "stripped or unsupported").state == EvidenceState.AMBIGUOUS
    assert EvidenceField.unknown("no bytes").state == EvidenceState.UNKNOWN
    assert EvidenceField.incomplete("cut short").state == EvidenceState.INCOMPLETE
    assert EvidenceField.not_observable("tls1.3 cert").state == EvidenceState.NOT_OBSERVABLE


def test_immutability_blocks_silent_conversion():
    f = EvidenceField.unknown("insufficient")
    with pytest.raises(Exception):  # frozen dataclass -> FrozenInstanceError
        f.state = EvidenceState.OBSERVED  # type: ignore[misc]


def test_value_or_refuses_nonconclusive():
    # The forbidden 'missing evidence reads as the value' path is blocked.
    assert EvidenceField.unknown("x").value_or("default") == "default"
    assert EvidenceField.not_observable("tls1.3").value_or(False) is False
    assert EvidenceField.ambiguous(False, "either").value_or(None) is None
    # Conclusive fields do return their value.
    assert EvidenceField.observed("TLSv1.2", "sh").value_or(None) == "TLSv1.2"
    assert EvidenceField.inferred(True, "basis").value_or(None) is True


def test_provenance_default_and_roundtrip():
    f = EvidenceField.observed("cert", "leaf", provenance=Provenance.INHERITED, frames=[10, 11])
    d = f.to_dict()
    assert d["provenance"] == "inherited"
    assert d["frames"] == [10, 11]
    assert EvidenceField.from_dict(d) == f


def test_is_conclusive():
    assert EvidenceField.observed(1, "b").is_conclusive
    assert EvidenceField.inferred(1, "b").is_conclusive
    assert not EvidenceField.unknown("b").is_conclusive
    assert not EvidenceField.ambiguous(1, "b").is_conclusive
