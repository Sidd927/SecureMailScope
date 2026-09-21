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


def _imported_modules(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


def test_backend_is_a_leaf_package():
    """No earlier package may import the backend. Phase 8 is a leaf (doc 21 §3)."""
    offenders = []
    for package in sorted(os.listdir(SRC)):
        pkg_dir = os.path.join(SRC, package)
        if package == "backend" or not os.path.isdir(pkg_dir):
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


def test_phase_seven_source_is_untouched():
    """Invariant 1: no Phase-7 security file changed on this branch."""
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
    violations = [f for f in changed if f.startswith(protected)]
    assert violations == [], violations
