"""
Phase-8 architecture tests (doc 21 §1, §3, §5, §15).

These assert structure rather than behaviour, in the spirit of the Phase-7 AST tests
that keep `posture/` and `ml/` apart. A backend that slowly grows its own severity
table would still pass every functional test in the suite; only a structural assertion
catches it.
"""
import ast
import os

import pytest

BACKEND = "src/securemailscope/backend"
SRC = "src/securemailscope"


def _modules(package_dir):
    for name in sorted(os.listdir(package_dir)):
        if name.endswith(".py"):
            path = os.path.join(package_dir, name)
            with open(path) as fh:
                yield name, ast.parse(fh.read(), filename=path)


def _is_type_checking_guard(node) -> bool:
    """True for `if TYPE_CHECKING:` / `if typing.TYPE_CHECKING:`."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def _imported_modules(tree, runtime_only: bool = True):
    """Modules a file imports.

    `runtime_only` skips `if TYPE_CHECKING:` blocks, which exist purely for annotations
    and create no runtime dependency. The distinction matters: `reporting/service.py`
    references backend types for typing while importing nothing from backend at import
    time, and a walker that could not tell the two apart would report a dependency
    that does not exist. The runtime claim is proved directly by a subprocess test
    that inspects `sys.modules`.
    """
    skip = set()
    if runtime_only:
        for node in ast.walk(tree):
            if _is_type_checking_guard(node):
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        skip.add(id(child))
    out = set()
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


def test_backend_is_a_leaf_package():
    """No earlier package may import the backend at runtime (doc 21 §3).

    `reporting/` is excluded because it is a LATER phase: Phase 9 composes over the
    backend, and doc 22 §3 states that direction. It still imports nothing from
    backend at runtime — asserted separately.
    """
    offenders = []
    for package in sorted(os.listdir(SRC)):
        pkg_dir = os.path.join(SRC, package)
        if package in ("backend", "reporting") or not os.path.isdir(pkg_dir):
            continue
        for name, tree in _modules(pkg_dir):
            for module in _imported_modules(tree):
                if "securemailscope.backend" in module:
                    offenders.append("%s/%s" % (package, name))
    assert offenders == [], offenders


def test_only_pipeline_constructs_the_posture_engine():
    """One orchestration path. A second would be a second interpretation."""
    constructors = []
    for name, tree in _modules(BACKEND):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in ("PostureEngine", "SecurityAnalysisEngine",
                                         "CrossSessionEngine", "AnomalyEngine"):
                constructors.append(name)
    assert set(constructors) == {"pipeline.py"}, constructors


def test_backend_never_constructs_a_security_conclusion():
    """The backend must not build findings, severities or scores itself."""
    forbidden = {"SecurityFinding", "CrossSessionFinding", "FusedFinding",
                 "IssueGroup", "PostureScore", "PostureAssessment", "MLAnomalyResult",
                 "Severity", "PrioritisedFinding", "RemediationGuidance"}
    offenders = []
    for name, tree in _modules(BACKEND):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in forbidden:
                offenders.append("%s: %s()" % (name, node.func.id))
    assert offenders == [], offenders


def test_backend_does_not_import_scoring_or_ml_internals():
    """Scoring and the feature layer are off limits: the backend recomputes nothing."""
    banned = ("securemailscope.posture.scoring", "securemailscope.posture.fusion",
              "securemailscope.posture.risk", "securemailscope.posture.prioritise",
              "securemailscope.posture.remediation", "securemailscope.ml.features",
              "securemailscope.ml.encoding", "securemailscope.ml.explain")
    offenders = []
    for name, tree in _modules(BACKEND):
        for module in _imported_modules(tree):
            if module in banned:
                offenders.append("%s -> %s" % (name, module))
    assert offenders == [], offenders


def test_only_pipeline_imports_the_ml_package():
    """The ML lane is reachable from exactly one place, and lazily."""
    importers = set()
    for name, tree in _modules(BACKEND):
        for module in _imported_modules(tree):
            if module.startswith("securemailscope.ml"):
                importers.add(name)
    assert importers <= {"pipeline.py"}, importers


def test_backend_defines_no_severity_or_score_constants():
    """No weights, thresholds or bands may be redefined outside the posture layer."""
    suspicious = {"SEVERITY_WEIGHT", "MIN_ASSESSED_FRACTION", "MAX_ML_ADJUSTMENT",
                  "FORMULAS", "SELECTED_FORMULA", "POSTURE_BANDS", "BAND_THRESHOLDS"}
    offenders = []
    for name, tree in _modules(BACKEND):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in suspicious:
                        offenders.append("%s: %s" % (name, target.id))
    assert offenders == [], offenders


def test_schema_declares_no_security_columns():
    """ADR-0017 Decision 1, asserted against the DDL text itself."""
    from securemailscope.backend.db import SCHEMA
    lowered = SCHEMA.lower()
    for token in ("severity", "risk_level", "finding", "anomaly_score",
                  "remediation", "certainty"):
        assert token not in lowered, token


def test_no_pydantic_model_redeclares_the_assessment():
    """ADR-0018 Decision 3: the assessment has one schema, and it is not here."""
    from securemailscope.backend import schemas
    for attr in dir(schemas):
        assert attr not in ("PostureAssessmentModel", "ScoreModel", "FindingModel",
                            "IssueGroupModel")
    # the assessment travels as an opaque mapping
    field = schemas.AssessmentResponse.model_fields["assessment"]
    assert field.annotation.__origin__ is dict


def test_core_package_has_no_runtime_dependencies():
    """Invariant 9: importing the analysis path must not require the backend extra."""
    import subprocess
    import sys
    code = (
        "import sys;"
        "import securemailscope.ingest, securemailscope.session,"
        "securemailscope.analysis, securemailscope.crosssession,"
        "securemailscope.posture, securemailscope.ml;"
        "assert 'fastapi' not in sys.modules;"
        "assert 'pydantic' not in sys.modules;"
        "print('clean')")
    env = dict(os.environ, PYTHONPATH="src")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env)
    assert out.returncode == 0, out.stderr.decode()
    assert b"clean" in out.stdout


def test_persistence_layer_imports_without_fastapi():
    """db/repository/lifecycle/service use the standard library only."""
    import subprocess
    import sys
    code = (
        "import sys;"
        "import securemailscope.backend.service;"
        "assert 'fastapi' not in sys.modules, sorted(m for m in sys.modules "
        "if 'fastapi' in m);"
        "print('clean')")
    env = dict(os.environ, PYTHONPATH="src")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env)
    assert out.returncode == 0, out.stderr.decode()


#: Files in the protected security packages that Phase 11 changes DELIBERATELY, under
#: ADR-0023. Phases 8-10 changed none of them, and the original blanket freeze was the
#: right guard for those phases. Phase 11 implements PS deliverables D-09..D-17, which
#: cannot be done without extracting new evidence, so the guard is re-pointed rather
#: than removed: an UNDECLARED edit to any protected file still fails.
#:
#: Adding a path here is a deliberate act that must be justified by an ADR. It is not
#: a way to make this test pass.
PHASE_11_DECLARED = {
    # D-09/D-17: key exchange and forward secrecy need the ServerHello key_share and
    # an interpretation of the cipher suite beside the existing raw value.
    "src/securemailscope/dissect/fields.py",
    "src/securemailscope/dissect/normalize.py",
    "src/securemailscope/session/base.py",
    "src/securemailscope/session/model.py",
    # D-10..D-14/D-16: new certificate and configuration rules.
    "src/securemailscope/analysis/model.py",
    "src/securemailscope/analysis/registry.py",
    "src/securemailscope/analysis/rules/__init__.py",
    "src/securemailscope/analysis/rules/tls_rules.py",
    "src/securemailscope/analysis/rules/certificate_rules.py",
    "src/securemailscope/analysis/rules/keyexchange_rules.py",
    "src/securemailscope/analysis/rules/configuration_rules.py",
    "src/securemailscope/posture/model.py",
    "src/securemailscope/posture/fusion.py",
}


def _protected_changes():
    import subprocess
    diff = subprocess.run(
        ["git", "diff", "--name-only", "v0.2.0-phase7", "HEAD"],
        capture_output=True, text=True)
    if diff.returncode != 0:                      # pragma: no cover - no git
        pytest.skip("git unavailable")
    changed = [line for line in diff.stdout.splitlines() if line]
    protected = ("src/securemailscope/posture/", "src/securemailscope/analysis/",
                 "src/securemailscope/crosssession/", "src/securemailscope/ml/",
                 "src/securemailscope/session/", "src/securemailscope/evidence/",
                 "src/securemailscope/dissect/", "src/securemailscope/ingest/")
    return [f for f in changed if f.startswith(protected)]


def test_phase_seven_source_changes_only_where_declared():
    """Invariant 1, as it now stands: no UNDECLARED Phase-7 security file changed."""
    undeclared = [f for f in _protected_changes() if f not in PHASE_11_DECLARED]
    assert undeclared == [], undeclared


def test_ml_lane_is_untouched_by_phase_eleven():
    """ADR-0024: A-02 stays PARTIAL, so no Phase-11 change may reach the ML lane.

    Measured (research/experiments/p11ai): the new features are constant, absent from
    45 of 46 captures, or a generator fingerprint. Routing them into `ml/` would
    worsen the 98.6% generator leak ADR-0015 identified. This asserts that decision
    structurally rather than trusting it to stay true.
    """
    touched = [f for f in _protected_changes()
               if f.startswith("src/securemailscope/ml/")]
    assert touched == [], touched


def test_evidence_contract_is_untouched():
    """The six evidence states and the Provenance vocabulary are Phase-2 canon.

    Phase 11 USES `Provenance` (which has existed unused since Phase 2) but must not
    redefine it: weakening a state's meaning would silently rewrite every prior
    assessment's semantics.
    """
    touched = [f for f in _protected_changes()
               if f.startswith("src/securemailscope/evidence/")]
    assert touched == [], touched


# ------------------------------------------------- Phase 9: reporting boundary
REPORTING = "src/securemailscope/reporting"


def test_security_engine_never_imports_reporting():
    """doc 22 §3: the security engine must not depend on its presentation layer."""
    offenders = []
    for package in ("posture", "analysis", "crosssession", "ml", "session",
                    "evidence", "dissect", "ingest"):
        pkg_dir = os.path.join(SRC, package)
        if not os.path.isdir(pkg_dir):
            continue
        for name, tree in _modules(pkg_dir):
            for module in _imported_modules(tree):
                if "securemailscope.reporting" in module:
                    offenders.append("%s/%s" % (package, name))
    assert offenders == [], offenders


def test_reporting_does_not_import_backend_at_runtime():
    """The dependency runs one way: backend composes reporting, never the reverse.

    Backend types are referenced under TYPE_CHECKING only, so there is no import cycle
    and no lazy import hiding one.
    """
    import subprocess
    import sys
    code = ("import sys; import securemailscope.reporting.service;"
            "bad=[m for m in sys.modules if m.startswith('securemailscope.backend')];"
            "assert not bad, bad; print('clean')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         env=dict(os.environ, PYTHONPATH="src"))
    assert out.returncode == 0, out.stderr.decode()


def test_reporting_html_and_projection_need_no_third_party_package():
    """JSON and HTML must work on a zero-dependency core install."""
    import subprocess
    import sys
    code = (
        "import sys;"
        "from securemailscope.reporting.projection import project;"
        "from securemailscope.reporting.html import render_html;"
        "third=[m for m in sys.modules if m.split('.')[0] in "
        "{'reportlab','fastapi','pydantic','jinja2','markupsafe','pypdf'}];"
        "assert not third, third; print('clean')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         env=dict(os.environ, PYTHONPATH="src"))
    assert out.returncode == 0, out.stderr.decode()


def test_reporting_never_computes_a_security_value():
    """doc 22 §5: no arithmetic or comparison on severity, score or band."""
    forbidden_names = {"compute_score", "band_for", "severity_weight", "SEVERITY_WEIGHT",
                       "MIN_ASSESSED_FRACTION", "MAX_ML_ADJUSTMENT", "FORMULAS"}
    offenders = []
    for name, tree in _modules(REPORTING):
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in forbidden_names:
                offenders.append("%s: %s" % (name, node.id))
            if isinstance(node, ast.Attribute) and node.attr in forbidden_names:
                offenders.append("%s: .%s" % (name, node.attr))
    assert offenders == [], offenders


def test_reporting_does_not_import_the_posture_engine_or_ml():
    """Reporting consumes the canonical dict, not the engines that produced it."""
    banned_prefixes = ("securemailscope.posture.engine",
                       "securemailscope.posture.scoring",
                       "securemailscope.posture.fusion",
                       "securemailscope.posture.risk",
                       "securemailscope.posture.prioritise",
                       "securemailscope.posture.remediation",
                       "securemailscope.ml",
                       "securemailscope.analysis",
                       "securemailscope.crosssession")
    offenders = []
    for name, tree in _modules(REPORTING):
        for module in _imported_modules(tree):
            if module.startswith(banned_prefixes):
                offenders.append("%s -> %s" % (name, module))
    assert offenders == [], offenders


def test_reporting_defines_no_severity_ordering_used_for_ranking():
    """`severity_rank` exists for display ordering only and must not reach ranking."""
    import securemailscope.reporting.projection as projection
    source = open(os.path.join(REPORTING, "projection.py")).read()
    # It may be used to pick the worst severity for a summary sentence, but the
    # prioritised list must never be sorted.
    assert ".sort(" not in source
    assert "sorted(a.get(\"prioritised\")" not in source
    assert "sorted(assessment" not in source
    assert projection is not None


#: Phase-8 backend files later phases are permitted to modify, and why. Every other
#: backend module — db, lifecycle, artifacts, pipeline, service, errors, limits — is
#: frozen, and this test is what keeps it that way.
#:
#: `repository.py` was added to this set in Phase 10 for one approved, documented
#: change (ADR-0022 Decision 3, doc 23 §6): a LEFT JOIN that returns the
#: `overall_posture` and `score_value` columns the assessment already stores, so a
#: history list costs one request instead of one per row. Nothing is recomputed and no
#: existing field changed name, type or meaning — asserted by
#: tests/test_dashboard_api_contract.py.
PHASE8_MUTABLE = {
    "src/securemailscope/backend/api.py",        # endpoint wiring (Phase 9, Phase 10)
    "src/securemailscope/backend/schemas.py",    # additive response fields
    "src/securemailscope/backend/repository.py",  # additive listing join (Phase 10)
}


def test_phase_eight_core_is_untouched():
    """Phase 8 is frozen apart from an explicit, justified allowlist."""
    import subprocess
    diff = subprocess.run(["git", "diff", "--name-only", "v0.3.0-phase8", "HEAD"],
                          capture_output=True, text=True)
    if diff.returncode != 0:                      # pragma: no cover - no git
        pytest.skip("git unavailable")
    changed = {f for f in diff.stdout.splitlines()
               if f.startswith("src/securemailscope/backend/")}
    assert changed <= PHASE8_MUTABLE, changed - PHASE8_MUTABLE


def test_frozen_backend_modules_really_are_frozen():
    """Names the modules no later phase may touch, so the allowlist cannot drift."""
    import subprocess
    diff = subprocess.run(["git", "diff", "--name-only", "v0.3.0-phase8", "HEAD"],
                          capture_output=True, text=True)
    if diff.returncode != 0:                      # pragma: no cover - no git
        pytest.skip("git unavailable")
    frozen = {"db.py", "lifecycle.py", "artifacts.py", "pipeline.py", "service.py",
              "errors.py", "limits.py", "__main__.py"}
    touched = {os.path.basename(f) for f in diff.stdout.splitlines()
               if f.startswith("src/securemailscope/backend/")}
    assert not (touched & frozen), touched & frozen


def test_repository_change_is_read_only_and_additive():
    """The Phase-10 exception must stay an exception: a read-side join, nothing more."""
    from securemailscope.backend.repository import RunRecord
    # the two new fields exist, default to None, and are optional
    record = RunRecord.new()
    assert record.overall_posture is None
    assert record.score_value is None
    # and the join is a SELECT, never a write
    source = open("src/securemailscope/backend/repository.py").read()
    assert "LEFT JOIN assessments" in source
    assert "UPDATE assessments" not in source
    assert "INSERT INTO assessments(overall_posture" not in source
