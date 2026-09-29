"""
Phase-10 tests: the dashboard security boundary (doc 23 §11, ADR-0022 Decision 4).

The frontend has no framework, so its safety is a discipline the code must hold rather
than a default it inherits. These tests make that discipline structural: they read the
shipped JavaScript and fail the build if a forbidden construct appears, and they drive
the static mount to prove no path escapes it.
"""
import os
import re

import pytest

STATIC = "src/securemailscope/dashboard/static"
DASHBOARD = "src/securemailscope/dashboard"


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


def _strip_comments(text):
    """Remove comments so a construct NAMED in a docstring is not a false positive."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    return text


def test_static_directory_ships_javascript():
    files = _js_files()
    assert files, "no dashboard JavaScript found"
    assert any(f.endswith("app.js") for f in files)


# ------------------------------------------------- forbidden DOM constructs
FORBIDDEN = [
    ("innerHTML", r"\.innerHTML\b"),
    ("outerHTML", r"\.outerHTML\b"),
    ("insertAdjacentHTML", r"\.insertAdjacentHTML\b"),
    ("document.write", r"document\s*\.\s*write\b"),
    ("eval", r"\beval\s*\("),
    ("new Function", r"\bnew\s+Function\s*\("),
    ("setTimeout with a string", r"setTimeout\s*\(\s*['\"]"),
    ("setInterval with a string", r"setInterval\s*\(\s*['\"]"),
    ("javascript: URL", r"javascript:"),
    ("dangerous srcdoc", r"\bsrcdoc\b"),
]


@pytest.mark.parametrize("name,pattern", FORBIDDEN,
                         ids=[n for n, _p in FORBIDDEN])
def test_forbidden_construct_absent_from_shipped_js(name, pattern):
    offenders = []
    for path in _js_files():
        if re.search(pattern, _strip_comments(_source(path))):
            offenders.append(path)
    assert offenders == [], "%s found in %s" % (name, offenders)


def test_forbidden_constructs_absent_from_html():
    html = _source(os.path.join(STATIC, "index.html"))
    for name, pattern in FORBIDDEN:
        assert not re.search(pattern, html), name
    # no inline event handlers and no inline script body
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler in index.html"
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), \
        "inline script body in index.html"


def test_no_external_resources_in_the_shell():
    """Offline-first: no CDN, no webfont, no third-party anything (doc 23 §14)."""
    html = _source(os.path.join(STATIC, "index.html"))
    css = _source(os.path.join(STATIC, "style.css"))
    for blob, label in ((html, "index.html"), (css, "style.css")):
        assert "http://" not in blob, label
        assert "https://" not in blob, label
        assert "//cdn" not in blob, label
    assert "@import" not in css


def test_no_npm_dependency_was_introduced():
    """Zero frontend dependencies (ADR-0022 Decision 1)."""
    for name in ("package.json", "package-lock.json", "yarn.lock",
                 "pnpm-lock.yaml", "node_modules"):
        assert not os.path.exists(name), name
        assert not os.path.exists(os.path.join(STATIC, name)), name


def test_no_build_step_artifacts():
    for name in ("vite.config.js", "webpack.config.js", "rollup.config.js",
                 "tsconfig.json", "dist"):
        assert not os.path.exists(os.path.join(STATIC, name)), name


# ------------------------------------------------------- URL discipline
def test_report_urls_come_from_a_fixed_allowlist():
    """No URL is ever taken from API data (doc 23 §11)."""
    api_js = _source(os.path.join(STATIC, "api.js"))
    assert "const FORMATS = new Set(['html', 'pdf', 'json'])" in api_js
    assert "UNSUPPORTED_REPORT_FORMAT" in api_js


def test_run_ids_are_validated_before_reaching_a_url():
    api_js = _source(os.path.join(STATIC, "api.js"))
    assert "/^[0-9a-f]{32}$/" in api_js
    assert "requireRunId" in api_js
    # every run-scoped endpoint validates
    for endpoint in ("/analyses/${requireRunId(runId)}",):
        assert endpoint in api_js


def test_tone_values_are_filtered_before_reaching_a_class():
    dom_js = _source(os.path.join(STATIC, "dom.js"))
    assert "sanitiseTone" in dom_js
    assert "/^[a-z_]+$/" in dom_js


def test_only_textcontent_is_used_for_data():
    """Text insertion only. `textContent` present, no markup assignment anywhere."""
    dom_js = _source(os.path.join(STATIC, "dom.js"))
    assert "textContent" in dom_js
    assert "createElement" in dom_js


# --------------------------------------------- python side of the boundary
def test_dashboard_is_a_leaf_package():
    """No earlier package imports the dashboard — not even reporting (doc 23 §3)."""
    import ast
    src = "src/securemailscope"
    offenders = []
    for package in sorted(os.listdir(src)):
        pkg_dir = os.path.join(src, package)
        if package in ("dashboard", "backend") or not os.path.isdir(pkg_dir):
            continue
        for name in sorted(os.listdir(pkg_dir)):
            if not name.endswith(".py"):
                continue
            tree = ast.parse(_source(os.path.join(pkg_dir, name)))
            for node in ast.walk(tree):
                module = None
                if isinstance(node, ast.ImportFrom):
                    module = node.module
                elif isinstance(node, ast.Import):
                    module = ",".join(a.name for a in node.names)
                if module and "securemailscope.dashboard" in module:
                    offenders.append("%s/%s" % (package, name))
    assert offenders == [], offenders


def test_dashboard_does_not_import_reporting_or_engines():
    """The console is not a second report generator and not a second engine."""
    import ast
    banned = ("securemailscope.reporting", "securemailscope.posture.engine",
              "securemailscope.posture.scoring", "securemailscope.posture.fusion",
              "securemailscope.ml", "securemailscope.analysis",
              "securemailscope.crosssession", "securemailscope.ingest",
              "securemailscope.dissect", "securemailscope.session")
    offenders = []
    for name in sorted(os.listdir(DASHBOARD)):
        if not name.endswith(".py"):
            continue
        tree = ast.parse(_source(os.path.join(DASHBOARD, name)))
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.ImportFrom):
                module = node.module
            elif isinstance(node, ast.Import):
                module = ",".join(a.name for a in node.names)
            if module and module.startswith(banned):
                offenders.append("%s -> %s" % (name, module))
    assert offenders == [], offenders


def test_dashboard_defines_no_severity_or_score_constants():
    import ast
    suspicious = {"SEVERITY_WEIGHT", "MIN_ASSESSED_FRACTION", "MAX_ML_ADJUSTMENT",
                  "FORMULAS", "SELECTED_FORMULA", "BAND_THRESHOLDS"}
    offenders = []
    for name in sorted(os.listdir(DASHBOARD)):
        if not name.endswith(".py"):
            continue
        tree = ast.parse(_source(os.path.join(DASHBOARD, name)))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in suspicious:
                        offenders.append("%s: %s" % (name, target.id))
    assert offenders == [], offenders


def test_projection_imports_no_third_party_package():
    """The projection must work on a zero-dependency core install."""
    import subprocess
    import sys
    code = ("import sys; from securemailscope.dashboard import project;"
            "third=[m for m in sys.modules if m.split('.')[0] in "
            "{'fastapi','pydantic','reportlab','jinja2','pypdf'}];"
            "assert not third, third; print('clean')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         env=dict(os.environ, PYTHONPATH="src"))
    assert out.returncode == 0, out.stderr.decode()


# ------------------------------------------------------- static serving
fastapi = pytest.importorskip("fastapi", reason="backend extra not installed")
pytest.importorskip("httpx", reason="httpx required by TestClient")
from fastapi.testclient import TestClient                      # noqa: E402

from securemailscope.backend.api import create_app              # noqa: E402
from securemailscope.backend.service import AnalysisService     # noqa: E402


def _client(tmp_path):
    return TestClient(create_app(service=AnalysisService(str(tmp_path / "d"))),
                      raise_server_exceptions=False)


def test_console_is_served(tmp_path):
    client = _client(tmp_path)
    for path, kind in (("/dashboard/", "text/html"),
                       ("/dashboard/app.js", "javascript"),
                       ("/dashboard/dom.js", "javascript"),
                       ("/dashboard/api.js", "javascript"),
                       ("/dashboard/style.css", "text/css"),
                       ("/dashboard/views/history.js", "javascript")):
        response = client.get(path)
        assert response.status_code == 200, path
        assert kind in response.headers["content-type"], path


@pytest.mark.parametrize("path", [
    "/dashboard/../../pyproject.toml",
    "/dashboard/../backend/api.py",
    "/dashboard/%2e%2e/%2e%2e/pyproject.toml",
    "/dashboard/....//....//pyproject.toml",
    "/dashboard/static/../../../etc/passwd",
])
def test_static_mount_refuses_traversal(tmp_path, path):
    response = _client(tmp_path).get(path)
    assert response.status_code in (400, 404)
    assert "securemailscope" not in response.text.lower() or \
        response.status_code == 404
    assert "root:" not in response.text


def test_static_mount_does_not_shadow_the_api(tmp_path):
    """Mounted after the router: an endpoint can never be captured by the mount."""
    client = _client(tmp_path)
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/analyses").status_code == 200


def test_console_serves_no_source_or_database(tmp_path):
    client = _client(tmp_path)
    for path in ("/dashboard/projection.py", "/dashboard/model.py",
                 "/dashboard/__init__.py", "/dashboard/securemailscope.db"):
        assert client.get(path).status_code == 404, path
