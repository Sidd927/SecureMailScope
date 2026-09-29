"""Phase-9 tests: the assessment -> ReportDocument projection (doc 22 §4, §5, §6)."""
import pytest

from securemailscope.reporting import project
from securemailscope.reporting.errors import MalformedAssessment
from securemailscope.reporting.model import (
    ALWAYS_PRESENT, RENDERER_VERSION, REPORT_SCHEMA_VERSION,
)
from securemailscope.reporting.projection import MAX_REPORT_FINDINGS
from tests.reporting_fixtures import (
    ai_enabled_assessment, base_assessment, critical_assessment, empty_assessment,
    hostile_assessment, insufficient_evidence, large_assessment,
)


# ------------------------------------------------------------------- metadata
def test_metadata_carries_identity_and_versions():
    doc = project(base_assessment())
    m = doc.metadata
    assert m.assessment_id == "a1b2c3d4e5f60718"
    assert m.capture_id == "f" * 64
    assert m.run_id == "0" * 32
    assert m.posture_schema_version == "1.0"
    assert m.posture_engine_version == "0.7.0"
    assert m.report_schema_version == REPORT_SCHEMA_VERSION
    assert m.renderer_version == RENDERER_VERSION
    assert m.report_schema_version != m.posture_engine_version


def test_generated_at_comes_from_the_assessment_not_the_clock():
    """ADR-0021 Decision 1: the report is a pure function of the assessment."""
    doc = project(base_assessment())
    assert doc.metadata.generated_at == "2026-09-21T10:00:00Z"
    again = project(base_assessment())
    assert again.metadata.generated_at == doc.metadata.generated_at


def test_projection_is_deterministic():
    a = project(base_assessment()).to_dict()
    b = project(base_assessment()).to_dict()
    assert a == b


# ---------------------------------------------------------------- refusal
@pytest.mark.parametrize("bad", [None, [], "assessment", 42])
def test_non_mapping_is_refused(bad):
    with pytest.raises(MalformedAssessment):
        project(bad)


def test_missing_canonical_keys_refused_not_guessed():
    doc = base_assessment()
    del doc["overall_posture"]
    with pytest.raises(MalformedAssessment) as exc:
        project(doc)
    assert "overall_posture" in exc.value.detail["missing"]
    assert exc.value.http_status == 422


# -------------------------------------------------------------- no recompute
def test_score_and_band_are_copied_verbatim():
    a = base_assessment()
    doc = project(a)
    assert doc.overall_posture == a["overall_posture"]
    assert "88" in doc.score_text
    posture = doc.section("posture")
    values = {f.label: f.value for f in posture.facts}
    assert values["Posture"] == "ADEQUATE"
    assert values["Score"] == "88 / 100"


def test_prioritised_order_is_preserved_not_resorted():
    """§5: the assessment already decided the order."""
    a = large_assessment(groups=10, abstentions=0)
    doc = project(a)
    table = doc.section("prioritised-findings").tables[0]
    ranks = [row[0] for row in table.rows]
    assert ranks == [str(e["rank"]) for e in a["prioritised"]]
    # severities are deliberately NOT in descending order in the fixture
    severities = [row[1].split()[-1] for row in table.rows]
    assert severities != sorted(severities)


def test_no_session_rows_are_fabricated():
    """`fused_findings` is absent from to_dict(); the report must not invent rows."""
    a = base_assessment()
    doc = project(a)
    detail = doc.section("issue-detail")
    assert len(detail.tables[0].rows) == len(a["issue_groups"])


# ------------------------------------------------------------------ vocabulary
def test_insufficient_evidence_is_never_softened():
    doc = project(insufficient_evidence())
    assert doc.overall_posture == "INSUFFICIENT_EVIDENCE"
    assert doc.overall_posture_label == "INSUFFICIENT EVIDENCE"
    for forbidden in ("Unknown", "Safe", "Secure", "Pass", "OK"):
        assert forbidden.lower() != doc.overall_posture_label.lower()
    summary = doc.section("executive-summary")
    assert any("withheld" in n.lower() for n in summary.notices)
    assert any("not a passing result" in n.lower() for n in summary.notices)


def test_insufficient_evidence_reports_no_score():
    doc = project(insufficient_evidence())
    assert doc.score_text == "Not scored"


def test_not_observable_survives_projection():
    doc = project(base_assessment())
    table = doc.section("abstentions").tables[0]
    assert table.rows[0][0] == "Not observable"
    assert "TLS 1.3" in table.rows[0][3]
    assert table.rows[0][4]          # resolved_by is never dropped


def test_certainty_and_observability_are_separate_columns():
    doc = project(critical_assessment())
    columns = doc.section("issue-detail").tables[0].columns
    assert "Certainty" in columns and "Observability" in columns
    row = doc.section("issue-detail").tables[0].rows[0]
    assert row[columns.index("Certainty")] == "UNCERTAIN"
    assert row[columns.index("Observability")] == "PARTIALLY OBSERVABLE"
    # severity is NOT reduced because certainty is low
    assert "CRITICAL" in row[0]


def test_severity_has_a_text_marker_for_greyscale():
    doc = project(critical_assessment())
    severity_cell = doc.section("issue-detail").tables[0].rows[0][0]
    assert "[!!!]" in severity_cell and "CRITICAL" in severity_cell


def test_contradictions_are_surfaced_as_notices():
    doc = project(critical_assessment())
    notices = " ".join(doc.section("issue-detail").notices)
    assert "Contradictory evidence" in notices


# -------------------------------------------------------------- always present
def test_mandatory_sections_render_even_when_empty():
    doc = project(empty_assessment())
    for section_id in ALWAYS_PRESENT:
        section = doc.section(section_id)
        assert section is not None, section_id
        assert not section.is_empty, section_id


def test_empty_assessment_states_absence_rather_than_vanishing():
    doc = project(empty_assessment())
    assert "no abstentions" in " ".join(
        doc.section("abstentions").paragraphs).lower()
    assert doc.section("limitations").notices
    assert doc.section("ml-transparency").facts


def test_sections_without_data_are_omitted():
    doc = project(empty_assessment())
    assert doc.section("protocol-posture") is None
    assert doc.section("remediation") is None
    assert doc.section("standards") is None


# ------------------------------------------------------------------- coverage
def test_coverage_accompanies_posture_in_the_summary():
    """§7: there is no layout in which a band appears without its coverage."""
    summary = project(base_assessment()).section("executive-summary")
    labels = [f.label for f in summary.facts]
    assert "Overall posture" in labels and "Evidence coverage" in labels
    assert labels.index("Evidence coverage") - labels.index("Overall posture") <= 2


def test_coverage_text_reports_fraction_and_counts():
    doc = project(base_assessment())
    assert "75.0%" in doc.coverage_text
    assert "3 of 4" in doc.coverage_text


def test_low_coverage_is_called_out():
    doc = project(insufficient_evidence())
    assert "16.7%" in doc.coverage_text
    assert any("insufficient" in n.lower()
               for n in doc.section("coverage").notices)


# ------------------------------------------------------------------------- ML
def test_ml_disabled_states_it_plainly():
    section = project(base_assessment()).section("ml-transparency")
    assert {f.label: f.value for f in section.facts}["ML lane"] == "Disabled"
    assert "deterministic" in " ".join(section.paragraphs).lower()


def test_ml_enabled_preserves_role_verbatim():
    section = project(ai_enabled_assessment()).section("ml-transparency")
    facts = {f.label: f.value for f in section.facts}
    assert facts["ML lane"] == "Enabled"
    assert facts["Role"] == "secondary prioritisation signal only"
    assert facts["Model"] == "robust-z-sum"
    text = " ".join(section.paragraphs + section.notices).lower()
    assert "does not determine any security fact" in text
    assert "not a vulnerability" in text
    assert "cannot move a finding from one tier" in text


def test_ml_section_never_claims_detection():
    section = project(ai_enabled_assessment()).section("ml-transparency")
    blob = " ".join(section.paragraphs + section.notices
                    + [f.value for f in section.facts]).lower()
    for forbidden in ("detected the attack", "ai detected", "identified the attacker",
                      "confirms an attack"):
        assert forbidden not in blob


def test_methodology_lists_ml_only_when_exercised():
    off = " ".join(project(base_assessment()).section("methodology").paragraphs)
    on = " ".join(project(ai_enabled_assessment()).section("methodology").paragraphs)
    assert "was not exercised" in off
    assert "Machine-learning secondary prioritisation signal" in on


# ------------------------------------------------------------------ discipline
def test_no_invented_metrics_anywhere():
    doc = project(base_assessment())
    blob = " ".join(
        [f.label for s in doc.sections for f in s.facts]
        + [p for s in doc.sections for p in s.paragraphs]).lower()
    for invented in ("packets analyzed", "packets analysed", "attack probability",
                     "confidence percentage", "compliance percentage",
                     "risk percentage", "detection rate", "affected hosts"):
        assert invented not in blob


def test_standards_section_disclaims_compliance():
    section = project(base_assessment()).section("standards")
    assert any("not a statement of compliance" in n.lower() for n in section.notices)


def test_remediation_disclaims_verification():
    section = project(base_assessment()).section("remediation")
    assert any("does not verify" in n.lower() for n in section.notices)


def test_limitations_are_carried_verbatim():
    a = base_assessment()
    notices = project(a).section("limitations").notices
    for limitation in a["limitations"]:
        assert limitation in notices


def test_provenance_carries_the_forensic_chain():
    facts = {f.label: f.value
             for f in project(base_assessment()).section("provenance").facts}
    assert facts["Capture identifier (SHA-256)"] == "f" * 64
    assert facts["Assessment identifier"] == "a1b2c3d4e5f60718"
    assert facts["Posture engine version"] == "0.7.0"
    assert facts["Report schema version"] == REPORT_SCHEMA_VERSION


def test_analysis_time_is_labelled_as_such():
    """ADR-0021: the shown time is the analysis time, and the report says so."""
    scope = project(base_assessment()).section("scope")
    note = [f.note for f in scope.facts if f.label == "Analysis timestamp"][0]
    assert "not of report generation" in note


# --------------------------------------------------------------------- limits
def test_large_assessment_is_truncated_visibly():
    doc = project(large_assessment(groups=MAX_REPORT_FINDINGS + 25, abstentions=5))
    assert doc.truncations
    assert any("truncated" in t for t in doc.truncations)
    assert len(doc.section("issue-detail").tables[0].rows) == MAX_REPORT_FINDINGS


def test_long_evidence_is_clipped_and_disclosed():
    a = base_assessment()
    a["prioritised"][0]["representative_finding"]["conclusion"] = "x" * 5000
    doc = project(a)
    assert any("truncated" in t for t in doc.truncations)
    assert any("…truncated]" in p for p in doc.section("issue-detail").paragraphs)


def test_large_assessment_projects_without_pathology():
    doc = project(large_assessment(groups=300, abstentions=200))
    assert len(doc.section("abstentions").tables[0].rows) == 200
    assert doc.sections


# --------------------------------------------------------------------- tables
def test_all_tables_are_rectangular():
    for builder in (base_assessment, insufficient_evidence, empty_assessment,
                    critical_assessment, ai_enabled_assessment, hostile_assessment):
        doc = project(builder())
        for section in doc.sections:
            for table in section.tables:
                for row in table.rows:
                    assert len(row) == len(table.columns), (
                        builder.__name__, section.section_id, table.caption)


def test_hostile_text_is_carried_as_data_not_interpreted():
    """The projection stores it verbatim; escaping is the renderer's job."""
    doc = project(hostile_assessment())
    assert doc.section("limitations").notices[0].startswith("<script>")
