"""
Phase-9 tests: report artifacts, the API, and cross-format semantic equivalence
(doc 22 §12, §13, §14, §16).

The load-bearing test here is `test_semantic_equivalence_across_formats` (§46): one
assessment rendered three ways must carry the same security facts. That is the
mitigation ADR-0020 promised in exchange for not rendering the PDF from the HTML.
"""
import io
import json
import os
import re

import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
pypdf = pytest.importorskip("pypdf", reason="pypdf required to verify PDFs")
from fastapi.testclient import TestClient                        # noqa: E402

from securemailscope.backend.api import create_app                # noqa: E402
from securemailscope.backend.lifecycle import JobState            # noqa: E402
from securemailscope.backend.repository import RunRecord          # noqa: E402
from securemailscope.backend.service import AnalysisService       # noqa: E402
from securemailscope.reporting.model import (                     # noqa: E402
    RENDERER_VERSION, REPORT_SCHEMA_VERSION,
)
from securemailscope.reporting.service import (                   # noqa: E402
    ReportService, safe_filename,
)
from tests.reporting_fixtures import (                            # noqa: E402
    HOSTILE, ai_enabled_assessment, base_assessment, critical_assessment,
    insufficient_evidence,
)


def _norm(text):
    return re.sub(r"\s+", " ", text)


def _pdf_text(data: bytes) -> str:
    reader = pypdf.PdfReader(io.BytesIO(data))
    return _norm("\n".join(p.extract_text() or "" for p in reader.pages))


def _seeded(tmp_path, assessment=None):
    """A service with one COMPLETED run whose assessment is the given document."""
    assessment = assessment or base_assessment()
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.store_assessment(assessment)
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        svc.repo.transition(run, target, capture_id=assessment["capture_id"])
    svc.repo.transition(run, JobState.COMPLETED,
                        assessment_id=assessment["assessment_id"])
    return svc, run.run_id, assessment


def _client(svc):
    return TestClient(create_app(service=svc), raise_server_exceptions=False)


# ------------------------------------------------------------------ artifacts
def test_report_is_stored_through_the_phase8_artifact_store(tmp_path):
    """ADR-0021 Decision 3: one artifact store, not two."""
    svc, run_id, assessment = _seeded(tmp_path)
    reports = ReportService(svc.repo, svc.artifacts)
    payload, meta = reports.get_or_create(run_id, assessment, "html")

    stored = [a for a in svc.repo.list_artifacts(run_id) if a.kind == "html"]
    assert len(stored) == 1
    assert stored[0].sha256 == meta["report_sha256"]
    assert stored[0].size_bytes == len(payload)
    svc.artifacts.verify(stored[0])          # re-reads and re-hashes
    assert meta["integrity"] == "OK"


def test_report_sha256_is_the_report_identity(tmp_path):
    import hashlib
    svc, run_id, assessment = _seeded(tmp_path)
    payload, meta = ReportService(svc.repo, svc.artifacts).get_or_create(
        run_id, assessment, "html")
    assert meta["report_sha256"] == hashlib.sha256(payload).hexdigest()
    # distinct from every other identity
    assert meta["report_sha256"] != meta["assessment_id"]
    assert meta["report_sha256"] != meta["capture_id"]
    assert meta["report_sha256"] != meta["artifact_id"]


def test_second_request_reuses_the_stored_artifact(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    reports = ReportService(svc.repo, svc.artifacts)
    first, meta1 = reports.get_or_create(run_id, assessment, "html")
    second, meta2 = reports.get_or_create(run_id, assessment, "html")
    assert first == second
    assert meta1["artifact_id"] == meta2["artifact_id"]
    assert len([a for a in svc.repo.list_artifacts(run_id) if a.kind == "html"]) == 1


def test_corrupted_report_is_regenerated_not_served(tmp_path):
    """A tampered artefact must never be handed over as if intact."""
    svc, run_id, assessment = _seeded(tmp_path)
    reports = ReportService(svc.repo, svc.artifacts)
    original, meta = reports.get_or_create(run_id, assessment, "html")

    record = [a for a in svc.repo.list_artifacts(run_id) if a.kind == "html"][0]
    with open(svc.artifacts.absolute(record.relative_path), "wb") as fh:
        fh.write(b"<html>TAMPERED</html>")
    assert not svc.artifacts.is_intact(record)

    served, meta2 = reports.get_or_create(run_id, assessment, "html")
    assert b"TAMPERED" not in served
    assert served == original
    assert meta2["artifact_id"] != meta["artifact_id"]
    assert meta2["integrity"] == "OK"


def test_stale_renderer_version_forces_regeneration(tmp_path):
    """ADR-0021 Decision 4: a report from another renderer is not silently served."""
    svc, run_id, assessment = _seeded(tmp_path)
    reports = ReportService(svc.repo, svc.artifacts)
    reports.get_or_create(run_id, assessment, "html")
    record = [a for a in svc.repo.list_artifacts(run_id) if a.kind == "html"][0]

    from securemailscope.reporting import service as svc_module
    assert svc_module._is_current(record) is True
    stale = record.__class__(
        **dict(record.to_dict(), relative_path=record.relative_path,
               original_filename="securemailscope-x.r0.1.v0.0.1.html"))
    assert svc_module._is_current(stale) is False


def test_missing_artifact_file_forces_regeneration(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    reports = ReportService(svc.repo, svc.artifacts)
    reports.get_or_create(run_id, assessment, "html")
    record = [a for a in svc.repo.list_artifacts(run_id) if a.kind == "html"][0]
    os.remove(svc.artifacts.absolute(record.relative_path))

    payload, meta = reports.get_or_create(run_id, assessment, "html")
    assert payload.startswith(b"<!DOCTYPE html>")
    assert meta["artifact_id"] != record.artifact_id


def test_json_is_not_stored_as_a_duplicate_artifact(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    payload, meta = ReportService(svc.repo, svc.artifacts).get_or_create(
        run_id, assessment, "json")
    assert json.loads(payload) == assessment
    assert meta["artifact_id"] is None and meta["integrity"] == "NOT_STORED"
    assert svc.repo.list_artifacts(run_id) == []


# ------------------------------------------------------------------ filenames
@pytest.mark.parametrize("hostile", [
    "../../../../etc/passwd", "a/b/c", "..\\..\\win.ini", "x\x00y", "a b; rm -rf /",
])
def test_download_filename_is_built_from_internal_ids_only(hostile):
    name = safe_filename(hostile, "pdf")
    assert name.startswith("securemailscope-")
    assert name.endswith(".pdf")
    for bad in ("/", "\\", "..", "\x00", " ", ";"):
        assert bad not in name


def test_unsupported_format_is_refused():
    from securemailscope.reporting.errors import UnsupportedFormat
    with pytest.raises(UnsupportedFormat):
        safe_filename("abc", "exe")


# ------------------------------------------------------------------------ API
def test_reports_listing(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    body = _client(svc).get("/api/v1/analyses/%s/reports" % run_id).json()
    formats = {i["format"]: i for i in body["items"]}
    assert set(formats) == {"html", "pdf", "json"}
    assert formats["html"]["renderer_available"] is True
    assert formats["html"]["generated"] is False
    assert formats["html"]["report_schema_version"] == REPORT_SCHEMA_VERSION
    assert formats["html"]["renderer_version"] == RENDERER_VERSION
    assert formats["pdf"]["filename"].endswith(".pdf")


def test_listing_reflects_generation(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    client = _client(svc)
    client.get("/api/v1/analyses/%s/reports/html" % run_id)
    item = {i["format"]: i for i in
            client.get("/api/v1/analyses/%s/reports" % run_id).json()["items"]}["html"]
    assert item["generated"] is True
    assert item["integrity"] == "OK"
    assert item["current"] is True
    assert len(item["report_sha256"]) == 64


def test_html_endpoint_content_type_and_headers(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    r = _client(svc).get("/api/v1/analyses/%s/reports/html" % run_id)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["x-assessment-id"] == assessment["assessment_id"]
    assert r.headers["x-report-schema-version"] == REPORT_SCHEMA_VERSION
    assert len(r.headers["x-report-sha256"]) == 64
    assert "content-disposition" not in r.headers      # renders in place
    assert r.text.startswith("<!DOCTYPE html>")


def test_pdf_endpoint_downloads_with_safe_name(tmp_path):
    svc, run_id, assessment = _seeded(tmp_path)
    r = _client(svc).get("/api/v1/analyses/%s/reports/pdf" % run_id)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    disposition = r.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "securemailscope-%s.pdf" % assessment["assessment_id"] in disposition
    assert ".." not in disposition and "/" not in disposition.split("filename=")[1]
    assert r.content[:5] == b"%PDF-"


def test_json_endpoint_equals_the_assessment_endpoint(tmp_path):
    """§42: report endpoints consume the canonical contract, never rebuild it."""
    svc, run_id, _ = _seeded(tmp_path)
    client = _client(svc)
    canonical = client.get("/api/v1/analyses/%s/assessment" % run_id).json()["assessment"]
    report = client.get("/api/v1/analyses/%s/reports/json" % run_id).json()
    assert report == canonical


def test_html_download_flag(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    r = _client(svc).get("/api/v1/analyses/%s/reports/html?download=true" % run_id)
    assert r.headers["content-disposition"].startswith("attachment;")


def test_unknown_format_is_structured_400(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    r = _client(svc).get("/api/v1/analyses/%s/reports/docx" % run_id)
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert set(body["error"]["detail"]["supported"]) == {"html", "pdf", "json"}


def test_unknown_run_is_404(tmp_path):
    svc, _, _ = _seeded(tmp_path)
    r = _client(svc).get("/api/v1/analyses/%s/reports/html" % ("a" * 32))
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.parametrize("hostile", ["../../etc/passwd", "' OR 1=1--", "zzz", "%00"])
def test_hostile_run_id_on_report_endpoints(tmp_path, hostile):
    svc, _, _ = _seeded(tmp_path)
    client = _client(svc)
    for url in ("/api/v1/analyses/%s/reports" % hostile,
                "/api/v1/analyses/%s/reports/html" % hostile):
        r = client.get(url)
        assert r.status_code in (400, 404)
        assert "passwd" not in r.text and "Traceback" not in r.text


def test_run_without_assessment_yields_404(tmp_path):
    svc = AnalysisService(str(tmp_path / "d"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.transition(run, JobState.FAILED, error_code="ANALYSIS_FAILED")
    r = _client(svc).get("/api/v1/analyses/%s/reports/html" % run.run_id)
    assert r.status_code == 404


def test_report_endpoints_leak_no_internals(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    client = _client(svc)
    for url in ("/api/v1/analyses/%s/reports" % run_id,
                "/api/v1/analyses/%s/reports/html" % run_id,
                "/api/v1/analyses/%s/reports/json" % run_id):
        text = client.get(url).text
        for leak in ("/Users/", "site-packages", "relative_path", "sqlite",
                     "Traceback"):
            assert leak not in text


# ----------------------------------------------------- failure isolation (§44)
def test_pdf_failure_leaves_assessment_and_html_intact(tmp_path, monkeypatch):
    """ADR-0019 Decision 4: a renderer failure is not an analysis failure."""
    svc, run_id, _ = _seeded(tmp_path)
    client = _client(svc)

    import securemailscope.reporting.service as rs

    def boom(document):
        from securemailscope.reporting.errors import RendererUnavailable
        raise RendererUnavailable("simulated absence", detail={"package": "reportlab"})

    monkeypatch.setattr("securemailscope.reporting.pdf.render_pdf", boom)

    failed = client.get("/api/v1/analyses/%s/reports/pdf" % run_id)
    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "REPORT_RENDERER_UNAVAILABLE"

    # the run is untouched
    run = client.get("/api/v1/analyses/%s" % run_id).json()
    assert run["state"] == "COMPLETED"
    assert run["error_code"] is None
    # and the other formats still work
    assert client.get("/api/v1/analyses/%s/reports/html" % run_id).status_code == 200
    assert client.get("/api/v1/analyses/%s/assessment" % run_id).status_code == 200
    # no fabricated artefact was stored
    assert not [a for a in svc.repo.list_artifacts(run_id) if a.kind == "pdf"]


def test_malformed_assessment_is_refused_not_rendered(tmp_path):
    broken = {"assessment_id": "x" * 16, "capture_id": "y" * 64}   # no overall_posture
    svc = AnalysisService(str(tmp_path / "d"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.store_assessment(broken)
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        svc.repo.transition(run, target, capture_id=broken["capture_id"])
    svc.repo.transition(run, JobState.COMPLETED, assessment_id=broken["assessment_id"])

    r = _client(svc).get("/api/v1/analyses/%s/reports/html" % run.run_id)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "MALFORMED_ASSESSMENT"


# --------------------------------------------- cross-format equivalence (§46)
@pytest.mark.parametrize("builder", [
    base_assessment, insufficient_evidence, critical_assessment,
    ai_enabled_assessment,
])
def test_semantic_equivalence_across_formats(tmp_path, builder):
    """One assessment, three renderings, same security facts.

    This is the mitigation ADR-0020 promised in exchange for composing the PDF from
    the report model rather than from the HTML.
    """
    assessment = builder()
    svc, run_id, _ = _seeded(tmp_path, assessment)
    client = _client(svc)

    html = client.get("/api/v1/analyses/%s/reports/html" % run_id).text
    pdf = _pdf_text(client.get("/api/v1/analyses/%s/reports/pdf" % run_id).content)
    canonical = client.get("/api/v1/analyses/%s/reports/json" % run_id).json()

    html_text = _norm(re.sub(r"<[^>]+>", " ", html))

    # identity
    assert canonical["assessment_id"] == assessment["assessment_id"]
    for blob in (html_text, pdf):
        assert assessment["assessment_id"] in blob
        assert assessment["capture_id"] in blob

    # posture: the same verdict word in every format
    posture_label = assessment["overall_posture"].replace("_", " ")
    assert canonical["overall_posture"] == assessment["overall_posture"]
    for blob in (html_text, pdf):
        assert posture_label in blob

    # score
    if assessment.get("score"):
        score_text = str(assessment["score"]["value"]).rstrip("0").rstrip(".")
        assert canonical["score"]["value"] == assessment["score"]["value"]
        for blob in (html_text, pdf):
            assert score_text in blob
    else:
        for blob in (html_text, pdf):
            assert "Not scored" in blob

    # coverage
    fraction = assessment["coverage"]["assessed_fraction"]
    coverage_text = "%.1f%%" % (fraction * 100.0)
    assert canonical["coverage"] == assessment["coverage"]
    for blob in (html_text, pdf):
        assert coverage_text in blob

    # Issue identity. The renderers show the group's title when it has one and fall
    # back to the humanised class, so equivalence means both formats made the SAME
    # choice — not that a particular string is present.
    for group in assessment["issue_groups"][:5]:
        needle = _norm(group.get("title") or "") or \
            group["issue_class"].replace("_", " ").capitalize()
        needle = needle[:60]
        for blob in (html_text, pdf):
            assert needle in blob, (group["issue_class"], posture_label)
        # severity travels with it, in both
        for blob in (html_text, pdf):
            assert group["severity"] in blob

    # standards
    for group in assessment["issue_groups"]:
        for citation in group.get("citations") or []:
            for blob in (html_text, pdf):
                assert citation["standard"] in blob

    # limitations
    for limitation in assessment["limitations"][:3]:
        snippet = _norm(limitation)[:50]
        for blob in (html_text, pdf):
            assert snippet in blob

    # ML role
    summary = assessment.get("model_summary") or {}
    if summary.get("role"):
        for blob in (html_text, pdf):
            assert summary["role"] in blob

    # abstentions
    for abstention in assessment.get("abstentions") or []:
        snippet = _norm(abstention["what_could_not_be_concluded"])[:40]
        for blob in (html_text, pdf):
            assert snippet in blob


def test_hostile_content_is_safe_in_every_format(tmp_path):
    from tests.reporting_fixtures import hostile_assessment
    svc, run_id, _ = _seeded(tmp_path, hostile_assessment())
    client = _client(svc)

    html = client.get("/api/v1/analyses/%s/reports/html" % run_id).text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html

    pdf = client.get("/api/v1/analyses/%s/reports/pdf" % run_id).content
    assert pdf[:5] == b"%PDF-"
    assert "alert(1)" in _pdf_text(pdf)      # present as text, not as markup

    served = client.get("/api/v1/analyses/%s/reports/json" % run_id).json()
    assert served["limitations"][0] == HOSTILE


# ---------------------------------------------------------------- determinism
def test_repeated_requests_return_identical_bytes(tmp_path):
    svc, run_id, _ = _seeded(tmp_path)
    client = _client(svc)
    for fmt in ("html", "pdf", "json"):
        a = client.get("/api/v1/analyses/%s/reports/%s" % (run_id, fmt)).content
        b = client.get("/api/v1/analyses/%s/reports/%s" % (run_id, fmt)).content
        assert a == b, fmt
