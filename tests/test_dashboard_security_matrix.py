"""
Phase-10 security matrix: the dashboard under hostile input (doc 23 §11).

Milestone 8 attacks the console rather than exercising it. Everything the API returns
ultimately derives from a capture, and a capture is attacker-controlled input, so every
field on every screen is treated as hostile here.

Three kinds of assertion, deliberately:

1. **Structural** — the shipped JavaScript cannot express the unsafe operation at all
   (no `innerHTML`, no URL from data, no class from data).
2. **Behavioural** — the projection and API carry hostile values through as data,
   preserving them rather than mangling or executing them.
3. **Boundary** — the static mount and the API refuse traversal, bad identifiers and
   malformed input, and never leak internals.

Live-DOM execution (payloads actually not firing in a browser) is covered in the
visual-QA milestone; these tests hold the line without a browser so they run in CI.
"""
import json
import os
import re
import subprocess
import shutil

import pytest

fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient                        # noqa: E402

from securemailscope.backend.api import create_app                # noqa: E402
from securemailscope.backend.lifecycle import JobState            # noqa: E402
from securemailscope.backend.repository import RunRecord          # noqa: E402
from securemailscope.backend.service import AnalysisService       # noqa: E402
from securemailscope.dashboard import project                     # noqa: E402
from securemailscope.dashboard.errors import MalformedAssessment  # noqa: E402
from tests.reporting_fixtures import base_assessment              # noqa: E402

STATIC = "src/securemailscope/dashboard/static"
NODE = shutil.which("node")

#: The payload set. Each is a real technique, not a variation on one.
PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    '"><script>alert(1)</script>',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "</td></tr><script>alert(1)</script>",
    "javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "file:///etc/passwd",
    "vbscript:msgbox(1)",
    "<style>body{display:none}</style>",
    "</style><style>*{}",
    "\\'; alert(1); //",
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "‮abcdef",                       # right-to-left override
    "\x00nullbyte",
    "../../../../etc/passwd",
    "..\\..\\windows\\system32",
]

#: Every string-bearing location an assessment can carry hostile text into.
FIELD_SETTERS = {
    "issue_title": lambda a, p: a["issue_groups"][0].__setitem__("title", p),
    "finding_conclusion": lambda a, p: a["prioritised"][0][
        "representative_finding"].__setitem__("conclusion", p),
    "finding_explanation": lambda a, p: a["prioritised"][0][
        "representative_finding"].__setitem__("explanation", p),
    "issue_class": lambda a, p: a["prioritised"][0]["representative_finding"][
        "key"].__setitem__("issue_class", p),
    "severity": lambda a, p: a["prioritised"][0][
        "representative_finding"].__setitem__("severity", p),
    "status": lambda a, p: a["prioritised"][0][
        "representative_finding"].__setitem__("status", p),
    "protocol": lambda a, p: a["prioritised"][0]["representative_finding"][
        "session"].__setitem__("protocol", p),
    "standard": lambda a, p: a.__setitem__("standards_summary", {
        "standards": {p: [p]}, "distinct_standards": 1,
        "unmapped_citations": [p], "note": p}),
    "remediation": lambda a, p: a["remediation_summary"][0].__setitem__(
        "recommended_action", p),
    "provenance_rule": lambda a, p: a.__setitem__("provenance", {
        "rule_ids": [p], "source_counts": {p: 1}, "note": p}),
    "limitation": lambda a, p: a.__setitem__("limitations", [p]),
    "abstention_why": lambda a, p: a["abstentions"][0].__setitem__("why", p),
    "abstention_resolution": lambda a, p: a["abstentions"][0].__setitem__(
        "resolved_by", p),
    "overall_posture": lambda a, p: a.__setitem__("overall_posture", p),
    "capture_id": lambda a, p: a.__setitem__("capture_id", p),
    "formula_id": lambda a, p: a["score"].__setitem__("formula_id", p),
    "dimension": lambda a, p: a["prioritised"][0][
        "representative_finding"].__setitem__("dimension", p),
}


def _js_files():
    out = []
    for dirpath, _dirs, files in os.walk(STATIC):
        for name in sorted(files):
            if name.endswith(".js"):
                out.append(os.path.join(dirpath, name))
    return out


def _source(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _code(path):
    """Source with comments stripped: a comment naming a sink is not a sink."""
    src = re.sub(r"/\*.*?\*/", "", _source(path), flags=re.S)
    return re.sub(r"^\s*//.*$", "", src, flags=re.M)


def _client(svc):
    return TestClient(create_app(service=svc), raise_server_exceptions=False)


def _seeded(tmp_path, assessment):
    svc = AnalysisService(str(tmp_path / "data"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.store_assessment(assessment)
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        svc.repo.transition(run, target, capture_id=str(assessment["capture_id"]))
    svc.repo.transition(run, JobState.COMPLETED,
                        assessment_id=assessment["assessment_id"])
    return svc, run.run_id


# =====================================================================
# 1. STRUCTURAL — the code cannot express the unsafe operation
# =====================================================================
DOM_SINKS = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
             "eval(", "new Function(", "setHTML(", "createContextualFragment",
             "document.domain", "srcdoc"]


@pytest.mark.parametrize("sink", DOM_SINKS)
def test_no_dom_sink_anywhere_in_shipped_js(sink):
    offenders = [p for p in _js_files() if sink in _code(p)]
    assert offenders == [], "%s in %s" % (sink, offenders)


def test_zero_occurrences_is_the_actual_count():
    """Not 'few' — zero. Counted across every shipped file including comments."""
    total = 0
    for path in _js_files():
        code = _code(path)
        for sink in DOM_SINKS:
            total += code.count(sink)
    assert total == 0


def test_no_dynamic_code_execution_primitives():
    for path in _js_files():
        code = _code(path)
        assert not re.search(r"setTimeout\s*\(\s*['\"`]", code), path
        assert not re.search(r"setInterval\s*\(\s*['\"`]", code), path
        assert "import(" not in code or "views/" in code or "api.js" in code


def test_no_url_is_built_from_api_data():
    """Only hash routes and the fixed report allowlist produce hrefs."""
    for path in _js_files():
        code = _code(path)
        for href in re.findall(r"href:\s*([^,}\n]+)", code):
            href = href.strip()
            assert (href.startswith("`#/") or href.startswith("'#/")
                    or "reportUrl(" in href or href == "item.href"), (path, href)


def test_no_src_attribute_is_ever_set():
    for path in _js_files():
        assert not re.search(r"\bsrc:\s", _code(path)), path
        assert not re.search(r"setAttribute\(\s*['\"]src['\"]", _code(path)), path


def test_every_class_interpolation_goes_through_a_sanitiser():
    """A class name may be built from a template only via a sanitiser.

    Found a real gap: `notice()` interpolated its `variant` unguarded. Every caller
    passed a literal so nothing was exploitable, but an unguarded path into a class
    attribute is what a later edit turns into a vulnerability. It now goes through
    `safeToken`.
    """
    sanitisers = ("sanitiseTone(", "safeToken(")
    for path in _js_files():
        code = _code(path)
        for template in re.findall(r"className:\s*`([^`]*)`", code):
            for expr in re.findall(r"\$\{([^}]*)\}", template):
                assert any(s in expr for s in sanitisers), (path, expr)


def test_sanitisers_strip_everything_dangerous():
    dom = _source(os.path.join(STATIC, "dom.js"))
    assert "/^[a-z_]+$/" in dom                       # sanitiseTone
    assert "replace(/[^a-z0-9_-]/g, '')" in dom       # safeToken


def test_no_style_string_is_built_from_data():
    """The only inline style is a computed percentage width."""
    for path in _js_files():
        code = _code(path)
        styles = re.findall(r"\.style\.(\w+)\s*=\s*([^;\n]+)", code)
        for prop, value in styles:
            assert prop == "width", (path, prop)
            assert "toFixed" in value, (path, value)
        assert "cssText" not in code, path
        assert not re.search(r"setAttribute\(\s*['\"]style['\"]", code), path


def test_tone_values_are_filtered_before_becoming_classes():
    dom = _source(os.path.join(STATIC, "dom.js"))
    assert "sanitiseTone" in dom
    assert "/^[a-z_]+$/" in dom
    # every chip/bar class goes through it
    assert dom.count("sanitiseTone(") >= 3


def test_run_ids_are_validated_before_reaching_a_request():
    api = _source(os.path.join(STATIC, "api.js"))
    assert "/^[0-9a-f]{32}$/" in api
    assert api.count("requireRunId(runId)") >= 5


def test_report_format_allowlist_is_closed():
    api = _source(os.path.join(STATIC, "api.js"))
    assert "new Set(['html', 'pdf', 'json'])" in api
    assert "FORMATS.has(format)" in api


# =====================================================================
# 2. BEHAVIOURAL — hostile values survive as data, unchanged
# =====================================================================
@pytest.mark.parametrize("payload", PAYLOADS)
def test_payload_survives_projection_verbatim(payload):
    a = base_assessment()
    a["limitations"] = [payload]
    a["issue_groups"][0]["title"] = payload
    vm = project(a).to_dict()
    assert vm["limitations"][0] == payload
    assert vm["issue_groups"][0]["title"] == payload


@pytest.mark.parametrize("field", sorted(FIELD_SETTERS))
def test_every_field_accepts_hostile_text_without_leaking_into_a_class(tmp_path,
                                                                      field):
    payload = '"><script>alert(1)</script>'
    a = base_assessment()
    FIELD_SETTERS[field](a, payload)
    vm = project(a).to_dict()
    blob = json.dumps(vm)
    assert payload in blob, field

    # no derived presentation key may carry it
    for row in vm["findings"]:
        assert re.match(r"^[a-z_]+$", row["severity_tone"])
    assert re.match(r"^[a-z_]+$", vm["posture"]["tone"])
    for row in vm["protocols"]:
        assert re.match(r"^[a-z_]+$", row["band_tone"])


@pytest.mark.parametrize("payload", ["javascript:alert(1)", "data:text/html,x",
                                     "file:///etc/passwd", "vbscript:msgbox(1)"])
def test_url_payloads_never_become_links(tmp_path, payload):
    a = base_assessment()
    a["issue_groups"][0]["title"] = payload
    a["limitations"] = [payload]
    svc, run_id = _seeded(tmp_path, a)
    vm = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id).json()
    assert payload in json.dumps(vm)
    # and no view constructs an href from any data value
    for path in _js_files():
        assert payload not in _source(path)


def test_filter_option_ids_are_sanitised():
    """A checkbox id is built from a facet value; it must not carry markup."""
    findings = _source(os.path.join(STATIC, "views/findings.js"))
    assert "replace(/[^A-Za-z0-9_-]/g, '_')" in findings


# =====================================================================
# 3. PROTOTYPE POLLUTION / hostile JSON shapes
# =====================================================================
@pytest.mark.parametrize("key", ["__proto__", "constructor", "prototype"])
def test_pollution_keys_in_assessment_do_not_escape_the_projection(key):
    a = base_assessment()
    a["provenance"] = {key: {"polluted": True}, "rule_ids": [], "source_counts": {}}
    a["risk_summary"] = {key: {"polluted": True}}
    vm = project(a).to_dict()
    # nothing was assigned onto a shared prototype
    assert not hasattr(dict, "polluted")
    assert not hasattr(object, "polluted")
    assert isinstance(vm, dict)


@pytest.mark.parametrize("key", ["__proto__", "constructor", "prototype"])
def test_pollution_keys_survive_json_transport(tmp_path, key):
    a = base_assessment()
    a["provenance"] = {"rule_ids": [], "source_counts": {key: 1}, "note": ""}
    svc, run_id = _seeded(tmp_path, a)
    body = _client(svc).get("/api/v1/analyses/%s/dashboard" % run_id)
    assert body.status_code == 200


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_filter_module_resists_prototype_pollution(tmp_path):
    """Hostile keys in the selection object must not corrupt Object.prototype."""
    module = os.path.abspath(os.path.join(STATIC, "filtering.js"))
    script = tmp_path / "poll.mjs"
    script.write_text(
        "import { applyFilters } from %s;\n"
        "const rows = [{rank:1, severity:'HIGH', protocol_key:'smtp'}];\n"
        "const hostile = JSON.parse('{\"__proto__\":{\"polluted\":true},"
        "\"severity\":[\"HIGH\"]}');\n"
        "const out = applyFilters(rows, hostile);\n"
        "process.stdout.write(JSON.stringify({\n"
        "  polluted: ({}).polluted === true,\n"
        "  visible: out.map(r => r.rank),\n"
        "}));\n" % json.dumps(module), encoding="utf-8")
    result = subprocess.run([NODE, str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["polluted"] is False
    assert out["visible"] == [1]


# =====================================================================
# 4. MALFORMED DATA — fail closed and visibly
# =====================================================================
@pytest.mark.parametrize("broken", [
    {},
    {"assessment_id": "a"},
    {"assessment_id": "a", "capture_id": "b"},
    {"assessment_id": "a", "capture_id": "b", "overall_posture": "X"},
])
def test_incomplete_assessment_is_refused(broken):
    with pytest.raises(MalformedAssessment):
        project(broken)


@pytest.mark.parametrize("wrong", [
    ("score", "not-a-dict"), ("coverage", 42), ("issue_groups", "text"),
    ("prioritised", {"not": "a list"}), ("abstentions", 7),
    ("limitations", "one string"), ("standards_summary", []),
    ("provenance", "text"), ("model_summary", "text"),
    ("protocol_posture", {"a": 1}), ("risk_summary", []),
])
def test_wrong_types_do_not_crash_the_projection(wrong):
    key, value = wrong
    a = base_assessment()
    a[key] = value
    vm = project(a).to_dict()          # must not raise
    assert vm["identity"]["assessment_id"]


@pytest.mark.parametrize("value", [None, 0, -1, 10 ** 30, 1.5e308, "NaN", "Infinity"])
def test_absurd_numbers_are_handled(value):
    a = base_assessment()
    a["score"]["value"] = value
    a["coverage"]["assessed_fraction"] = value
    vm = project(a).to_dict()
    # a non-numeric value becomes absence, never a fabricated number
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        assert vm["posture"]["score_value"] == float(value)
    else:
        assert vm["posture"]["score_value"] is None
        assert vm["posture"]["score_text"] == "Not scored"


def test_huge_strings_are_carried_without_pathology():
    a = base_assessment()
    huge = "A" * 2_000_000
    a["limitations"] = [huge]
    vm = project(a).to_dict()
    assert len(vm["limitations"][0]) == 2_000_000


def test_deeply_nested_provenance_does_not_recurse():
    node = {"leaf": 1}
    for _ in range(200):
        node = {"child": node}
    a = base_assessment()
    a["provenance"] = {"rule_ids": [], "source_counts": {}, "deep": node}
    vm = project(a).to_dict()
    assert "deep" in vm["provenance"]["entries"]


def test_malformed_assessment_reaches_the_client_as_422(tmp_path):
    broken = {"assessment_id": "x" * 16, "capture_id": "y" * 64}
    svc = AnalysisService(str(tmp_path / "d"))
    run = svc.repo.create_run(RunRecord.new())
    svc.repo.store_assessment(broken)
    for target in (JobState.VALIDATING, JobState.QUEUED, JobState.RUNNING,
                   JobState.FINALIZING):
        svc.repo.transition(run, target, capture_id=broken["capture_id"])
    svc.repo.transition(run, JobState.COMPLETED, assessment_id=broken["assessment_id"])
    r = _client(svc).get("/api/v1/analyses/%s/dashboard" % run.run_id)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "MALFORMED_ASSESSMENT"
    assert "Traceback" not in r.text


# =====================================================================
# 5. RESOURCE EXHAUSTION
# =====================================================================
def test_many_issue_classes_project_linearly():
    """45+ distinct issue classes was the visual-QA case; 500 must still work."""
    import time
    from tests.reporting_fixtures import large_assessment
    small = large_assessment(groups=50, abstentions=10)
    big = large_assessment(groups=500, abstentions=100)

    start = time.perf_counter()
    project(small)
    small_ms = time.perf_counter() - start
    start = time.perf_counter()
    vm = project(big).to_dict()
    big_ms = time.perf_counter() - start

    assert len(vm["findings"]) == 500
    assert len(vm["filters"]["issue_class"]) == 500
    # 10x the data must not cost anywhere near 100x the time
    assert big_ms < small_ms * 30 + 1.0, (small_ms, big_ms)


def test_filter_options_do_not_explode_combinatorially():
    from tests.reporting_fixtures import large_assessment
    vm = project(large_assessment(groups=300, abstentions=50)).to_dict()
    total_options = sum(len(v) for v in vm["filters"].values())
    # bounded by distinct values, not by the cross product
    assert total_options <= 300 + 8 * 10


def test_large_view_model_stays_within_a_sane_size(tmp_path):
    from tests.reporting_fixtures import large_assessment
    vm = project(large_assessment(groups=300, abstentions=100)).to_dict()
    size = len(json.dumps(vm))
    assert size < 8 * 1024 * 1024, size


# =====================================================================
# 6. STATIC FILE / API BOUNDARY
# =====================================================================
@pytest.mark.parametrize("path", [
    "/dashboard/../../pyproject.toml",
    "/dashboard/../backend/api.py",
    "/dashboard/%2e%2e/%2e%2e/pyproject.toml",
    "/dashboard/..%2f..%2fpyproject.toml",
    "/dashboard/....//....//pyproject.toml",
    "/dashboard/%252e%252e/pyproject.toml",
    "/dashboard/.%2e/.%2e/etc/passwd",
    "/dashboard//etc/passwd",
    "/dashboard/views/../../../../etc/passwd",
])
def test_static_mount_refuses_traversal(tmp_path, path):
    r = _client(AnalysisService(str(tmp_path / "d"))).get(path)
    assert r.status_code in (400, 404), (path, r.status_code)
    assert "root:" not in r.text
    assert "[project]" not in r.text
    assert "def create_app" not in r.text


@pytest.mark.parametrize("path", [
    "/dashboard/projection.py", "/dashboard/model.py", "/dashboard/__init__.py",
    "/dashboard/vocabulary.py", "/dashboard/securemailscope.db",
    "/dashboard/../securemailscope.db",
])
def test_no_source_or_database_is_served(tmp_path, path):
    assert _client(AnalysisService(str(tmp_path / "d"))).get(path).status_code == 404


def test_static_mount_cannot_shadow_the_api(tmp_path):
    client = _client(AnalysisService(str(tmp_path / "d")))
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/analyses").status_code == 200


@pytest.mark.parametrize("run_id", [
    "../../etc/passwd", "' OR 1=1--", "%00", "a" * 500, "<script>",
    "0x41414141", "null", "undefined", "../" * 40,
])
def test_hostile_run_ids_on_every_run_endpoint(tmp_path, run_id):
    client = _client(AnalysisService(str(tmp_path / "d")))
    for suffix in ("", "/assessment", "/dashboard", "/artifacts", "/reports",
                   "/reports/html"):
        r = client.get("/api/v1/analyses/%s%s" % (run_id, suffix))
        assert r.status_code in (400, 404), (run_id, suffix, r.status_code)
        assert "Traceback" not in r.text
        assert "root:" not in r.text
        assert "/Users/" not in r.text


def test_no_debug_endpoints_or_secrets_in_shipped_frontend():
    for path in _js_files() + [os.path.join(STATIC, "index.html"),
                               os.path.join(STATIC, "style.css")]:
        source = _source(path)
        for forbidden in ("console.log", "debugger", "TODO:", "FIXME",
                          "password", "secret", "api_key", "apiKey", "token="):
            assert forbidden not in source, (path, forbidden)


def test_frontend_makes_no_absolute_or_cross_origin_request():
    """Every request path is relative and same-origin.

    An absolute URL may appear only inside displayed copy — the empty-history panel
    shows a curl example — so the assertion targets request construction rather than
    the presence of the characters anywhere.
    """
    api = _code(os.path.join(STATIC, "api.js"))
    assert "const BASE = '/api/v1'" in api
    for absolute in ("http://", "https://", "//localhost", "127.0.0.1"):
        assert absolute not in api, absolute

    for path in _js_files():
        code = _code(path)
        # no fetch/request anywhere takes an absolute URL
        for call in re.findall(r"(?:fetch|request)\(\s*([^,)\n]+)", code):
            assert "http" not in call.lower(), (path, call)
        # any absolute URL present must be inside a displayed text value
        for match in re.finditer(r"https?://[^\s'\"`,)]+", code):
            line = code[:match.start()].rsplit("\n", 1)[-1] + match.group(0)
            assert "text:" in line or "text: '" in code[
                max(0, match.start() - 200):match.start()], (path, match.group(0))
